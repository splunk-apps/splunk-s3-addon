import sys, time, os, csv
import httplib, urllib, hashlib, base64, hmac, urlparse, md5
import xml.dom.minidom, xml.sax.saxutils
import logging
import tarfile, gzip

ENDPOINT_HOST_PORT = "s3.amazonaws.com"

# set up logging suitable for splunkd consumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

SCHEME = """<scheme>
    <title>Amazon S3</title>
    <description>Get data from Amazon S3.</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="name">
                <title>Resource name</title>
                <description>An S3 resource name without the leading s3://.  For example, for s3://bucket/file.txt specify bucket/file.txt.  You can also monitor a whole bucket (for example by specifying 'bucket'), or files within a sub-directory of a bucket (for example 'bucket/some/directory/'; note the trailing slash).</description>
            </arg>

            <arg name="key_id">
                <title>Key ID</title>
                <description>Your Amazon key ID.</description>
            </arg>

            <arg name="secret_key">
                <title>Secret key</title>
                <description>Your Amazon secret key.</description>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

def get_encoded_csv_file_path(checkpoint_dir, conf_stanza):
    # encode the URI (simply to make the file name recognizable)
    name = ""
    for i in range(len(conf_stanza)):
        if conf_stanza[i].isalnum():
            name += conf_stanza[i]
        else:
            name += "_"

    # trim the length in case the name is too long
    name = name[:30]

    # MD5 the URL
    m = md5.new()
    m.update(conf_stanza)
    name += "_" + m.hexdigest() + ".csv.gz"

    return os.path.join(checkpoint_dir, name)

# number of expected columns in the CSV file
Checkpointer_COLS = 3
# in seconds, what is the minimum time before we sync checkpoints to disk
Checkpointer_min_sync_interval_sec = 10

class Checkpointer:
    class Item:
        def __init__(self, total_bytes, completed):
            self.total_bytes = total_bytes
            self.completed = completed

        def get_total_bytes(self):
            return self.total_bytes

        def is_completed(self):
            return self.completed

    def __init__(self, checkpoint_dir, conf_stanza):
        self.chkpnt_file_name = get_encoded_csv_file_path(checkpoint_dir, conf_stanza)
        self.chkpnt_dict = {}
        # load checkpoint into memory
        self._load()
        self.last_chkpnt_time = 0.0

    # returns a Checkpointer.Item object
    def load_item(self, item):
        return self.chkpnt_dict.get(item, Checkpointer.Item(0, False))

    # write a checkpoint item
    def save_item(self, item, total_bytes, completed = False):
        self.chkpnt_dict[item] = Checkpointer.Item(total_bytes, completed)

        # sync to disk immediately on "completed"; otherwise, sync to disk
        # no more frequently than the minimum interval
        if completed or time.time() > self.last_chkpnt_time + Checkpointer_min_sync_interval_sec:
            self.sync()

    # syncs to disk all checkpoint info immediately
    def sync(self):
        tmp_file = self.chkpnt_file_name + ".tmp"
        f = None
        try:
            f = gzip.open(tmp_file, "wb")
        except Exception, e:
            logging.error("Unable to open file='%s' for writing: %s" % \
                self.chkpnt_file_name, str(e))

        writer = csv.writer(f)

        for key, item in self.chkpnt_dict.iteritems():
            writer.writerow([key, str(item.total_bytes), str(item.completed)])

        f.close()
        os.rename(tmp_file, self.chkpnt_file_name)
        self.last_chkpnt_time = time.time()

    def _load(self):
        f = self._open_checkpoint_file("rb")
        if f is None:
            return

        reader = csv.reader(f)
        line = 1
        for row in reader:
            if len(row) >= Checkpointer_COLS:
                # the first column of the row is the item name;
                # store it in the dict
                try:
                    b = None
                    if row[2].lower() == "true":
                        b = True
                    elif row[2].lower() == "false":
                        b = False
                    else:
                        # invalid value
                        raise Exception

                    self.chkpnt_dict[row[0]] = Checkpointer.Item(int(row[1]), b)
                except:
                    logging.error("The CSV file='%s' line=%d appears to be corrupt." % \
                        (self.chkpnt_file_name, line))
                    raise
            else:
                logging.warn("The CSV file='%s' line=%d contains less than %d rows." % \
                    (self.chkpnt_file_name, line, Checkpointer_COLS))
            line += 1

        f.close()

    def _open_checkpoint_file(self, mode):
        if not os.path.exists(self.chkpnt_file_name):
            return None
        # try to open this file
        f = None
        try:
            f = gzip.open(self.chkpnt_file_name, mode)
        except Exception, e:
            logging.error("Error opening '%s': %s" % (self.chkpnt_file_name, str(e)))
            return None
        return f

def string_to_sign(method, http_date, resource):
    # "$method\n$contentMD5\n$contentType\n$httpDate\n$xamzHeadersToSign$resource"
    return "%s\n\n\n%s\n%s" % (method, http_date, resource)

# returns "Authorization" header string
def get_auth_header_value(method, key_id, secret_key, http_date, resource):
    to_sign = string_to_sign(method, http_date, resource)
    logging.debug("String to sign=%s" % repr(to_sign))

    signature = base64.encodestring(hmac.new(str(secret_key), to_sign, hashlib.sha1).digest()).strip()

    return "AWS %s:%s" % (key_id, signature)

def put_header(conn, k, v):
    logging.debug("Adding header %s: %s" % (k, v))
    conn.putheader(k, v)

def gen_date_string():
    st = time.localtime()
    tm = time.mktime(st)
    return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(tm))

# query_string is expected to have been escaped by the caller
def get_http_connection(key_id, secret_key, bucket, obj, use_bucket_as_host = True, query_string = None):
    method = "GET"
    host = bucket + "." + ENDPOINT_HOST_PORT
    if not use_bucket_as_host:
        host = ENDPOINT_HOST_PORT

    conn = httplib.HTTPConnection(host)
    logging.info("Connecting to %s." % host)
    conn.connect()

    unescaped_path_to_sign = "/" + bucket + "/"
    unescaped_path_to_req = "/"
    if obj:
        unescaped_path_to_sign += obj
        unescaped_path_to_req += obj

    if not use_bucket_as_host:
        unescaped_path_to_req = unescaped_path_to_sign

    date_str = gen_date_string()

    path = urllib.quote(unescaped_path_to_req)
    if query_string:
        path += query_string
    logging.debug("%s %s" % (method, path))
    conn.putrequest(method, path)
    put_header(conn, "Authorization", get_auth_header_value(method, key_id, \
        secret_key, date_str, unescaped_path_to_sign))
    put_header(conn, "Date", date_str)
    conn.endheaders()

    return conn

def log_response(resp):
    status, reason = resp.status, resp.reason
    s = "status=%s reason=\"%s\"" % (str(status), str(reason))
    if status == 200:
        logging.debug(s)
    else:
        logging.error(s)

# parse the amazon error string and extract the message
def get_amazon_error(s):
    try:
        doc = xml.dom.minidom.parseString(s)
        root = doc.documentElement
        messages = root.getElementsByTagName("Message")
        if messages and messages[0].firstChild and \
           messages[0].firstChild.nodeType == messages[0].firstChild.TEXT_NODE:
            return messages[0].firstChild.data
        return ""
    except xml.parsers.expat.ExpatError, e:
        return s

# prints XML error data to be consumed by Splunk
def print_error_old(s):
    impl = xml.dom.minidom.getDOMImplementation()
    doc = impl.createDocument(None, "message", None)
    top_element = doc.documentElement
    text = doc.createTextNode(s)
    top_element.appendChild(text)
    sys.stdout.write(doc.toxml())

# prints XML error data to be consumed by Splunk
def print_error(s):
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)

def validate_conf(config, key):
    if key not in config:
        raise Exception, "Invalid configuration received from Splunk: key '%s' is missing." % key

# read XML configuration passed from splunkd
def get_config():
    config = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "key_id")
        validate_conf(config, "secret_key")
        validate_conf(config, "checkpoint_dir")
    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

# for url s3://igor-blah/splunk_logs/, the return value would be:
#   ('igor-blah', 'splunk_logs/', 'splunk_logs/')
# for url s3://igor-blah/file.txt
#   ('igor-blah', None, 'file.txt')
# for url s3://igor-blah/dir/file.txt
#   ('igor-blah', 'dir/', 'dir/file.txt')
# for url s3://igor-blah/dir/dir2/file.txt
#   ('igor-blah', 'dir/dir2/', 'dir/dir2/file.txt')
# for url s3://igor-blah
#   ('igor-blah', None, None)
def read_from_s3_uri(url):
    u = urlparse.urlparse(str(url))
    bucket = u.netloc
    obj = None
    subdir = None
    if u.path:
        obj = u.path[1:]  # trim the leading slash
        subdir = "/".join(obj.split("/")[:-1])
        if subdir:
            subdir += "/"
    logging.debug("Extracted from url=%s bucket=%s subdir=%s object=%s" % (url, bucket, subdir, obj))
    if not subdir:
        subdir = None
    if not obj:
        obj = None
    return (bucket, subdir, obj)

class HTTPResponseWrapper:
    def __init__(self, resp):
        self.resp = resp

def init_stream():
    sys.stdout.write("<stream>")

def fini_stream():
    sys.stdout.write("</stream>")

def send_data(source, buf):
    sys.stdout.write("<event unbroken=\"1\"><data>")
    sys.stdout.write(xml.sax.saxutils.escape(buf))
    sys.stdout.write("</data>\n<source>")
    sys.stdout.write(xml.sax.saxutils.escape(source))
    sys.stdout.write("</source></event>\n")

def send_done_key(source):
    sys.stdout.write("<event unbroken=\"1\"><source>")
    sys.stdout.write(xml.sax.saxutils.escape(source))
    sys.stdout.write("</source><done/></event>\n")

# returns a list of all objects from a bucket
def get_objs_from_bucket(key_id, secret_key, bucket, subdir = None):
    query_string = None
    if subdir:
        query_string = "?prefix=%s&delimiter=/" % urllib.quote(subdir)
    conn = get_http_connection(key_id, secret_key, bucket, obj = None, query_string = query_string)
    resp = conn.getresponse()
    log_response(resp)
    if resp.status != 200:
        raise Exception, "AWS HTTP request return status code %d (%s): %s" % \
            (resp.status, resp.reason, get_amazon_error(resp.read()))
    bucket_listing = resp.read()
    conn.close()

    # parse AWS's bucket listing response
    objs = []
    doc = xml.dom.minidom.parseString(bucket_listing)
    root = doc.documentElement

    key_nodes = root.getElementsByTagName("Key")
    for key in key_nodes:
        if key.firstChild.nodeType == key.firstChild.TEXT_NODE:
            objs.append(key.firstChild.data)

    return objs

def run():
    config = get_config()
    url = config["name"]
    bucket, subdir, obj = read_from_s3_uri(url)
    key_id = config["key_id"]
    secret_key = config["secret_key"]

    chk = Checkpointer(config["checkpoint_dir"], url)

    if obj and (not subdir or obj != subdir):
        # object-level URL provided (e.g. s3://bucket/object.txt) that does
        # not appear to be a directory (no ending slash)
        if not chk.load_item(url).is_completed():
            # there is no checkpoint for this URL: process
            init_stream()
            total_bytes = request_one_object(url, key_id, secret_key, bucket, obj)
            fini_stream()
            chk.save_item(url, total_bytes, completed = True)
        else:
            logging.info("URL %s already processed.  Skipping.")
    else:
        # bucket-level URL provided (e.g. s3://bucket), or a directory-level
        # URL (e.g. s3://bucket/some/subdir/)
        init_stream()
        while True:
            logging.debug("Checking for objects in bucket %s" % bucket)
            objs = get_objs_from_bucket(key_id, secret_key, bucket, subdir)
            for o in objs:
                if subdir and not o.startswith(subdir):
                    logging.debug("obj=%s does not start with %s.  Skipping.", subdir)
                    continue
                obj_url = "s3://" + bucket + "/" + o
                if not chk.load_item(obj_url).is_completed():
                    logging.info("Processing %s" % obj_url)
                    total_bytes = request_one_object(obj_url, key_id, secret_key, bucket, o)
                    chk.save_item(obj_url, total_bytes, completed = True)

            # check every 60 seconds for new entries
            time.sleep(60)
        fini_stream()

def request_one_object(url, key_id, secret_key, bucket, obj):
    assert bucket and obj

    conn = get_http_connection(key_id, secret_key, bucket, obj)
    resp = conn.getresponse()
    log_response(resp)
    if resp.status != 200:
        raise Exception, "Amazon HTTP request to '%s' returned status code %d (%s): %s" % \
            (url, resp.status, resp.reason, get_amazon_error(resp.read()))

    translator = get_data_translator(url, resp)

    cur_src = ""
    buf = translator.read()
    bytes_read = len(buf)
    while len(buf) > 0:
        if cur_src and translator.source() != cur_src:
            send_done_key(cur_src)
        cur_src = translator.source()
        send_data(translator.source(), buf)
        buf = translator.read()
        bytes_read += len(buf)

    if cur_src:
        send_done_key(cur_src)

    translator.close()
    conn.close()
    sys.stdout.flush()

    logging.info("Done reading. Read bytes=%d", bytes_read)
    return bytes_read

# Handles file reading from tar archives.  From the tarfile module:
# fileobj must support: read(), readline(), readlines(), seek() and tell().
class TarTranslator():
    def __init__(self, src, tar):
        self.tar = tar
        self.member = self.tar.next()
        self.member_f = self.tar.extractfile(self.member)
        self.translator = None
        self.base_source = src
        if self.member:
            self.src = self.base_source + ":" + self.member.name
            if self.member_f:
                self.translator = get_data_translator(self.src, self.member_f)

    def read(self, sz = 8192):
        while True:
            while self.member and self.member_f is None:
                self.member = self.tar.next()
                if self.member:
                    self.member_f = self.tar.extractfile(self.member)
                    self.src = self.base_source + ":" + self.member.name
                    self.translator = get_data_translator(self.src, self.member_f)

            if not self.member:
                return "" # done

            buf = self.translator.read(sz)
            if len(buf) > 0:
                return buf
            self.member_f = None
            self.translator = None

    def close(self):
        self.tar.close()

    def source(self):
        return self.src

class FileObjTranslator():
    def __init__(self, src, fileobj):
        self.src = src
        self.fileobj = fileobj

    def read(self, sz = 8192):
        return self.fileobj.read(sz)

    def close(self):
        return self.fileobj.close()

    def source(self):
        return self.src

class GzipFileTranslator():
    def __init__(self, src, fileobj):
        self.src = src
        self.fileobj = fileobj

    def read(self, sz = 8192):
        return self.fileobj.read(sz)

    def close(self):
        return self.fileobj.close()

    def source(self):
        return self.src

def get_data_translator(url, fileobj):
    if url.endswith(".tar"):
        return TarTranslator(url, tarfile.open(None, "r|", fileobj))
    elif url.endswith(".tar.gz") or url.endswith(".tgz"):
        return TarTranslator(url, tarfile.open(None, "r|gz", fileobj))
    elif url.endswith(".tar.bz2"):
        return TarTranslator(url, tarfile.open(None, "r|bz2", fileobj))
    elif url.endswith(".gz"):
        # it's lame that gzip.GzipFile requires tell() and seek(), and our
        # "fileobj" does not supply these; wrap this with the object that is
        # used by the tarfile module
        return GzipFileTranslator(url, tarfile._Stream("", "r", "gz", fileobj, tarfile.RECORDSIZE))
    else:
        return FileObjTranslator(url, fileobj)

def do_scheme():
    print SCHEME

def get_validation_data():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

    logging.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logging.debug("XML: found item")

        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logging.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data

# make sure that the amazon credentials are good
def validate_arguments():
    val_data = get_validation_data()
    key_id = val_data["key_id"]
    secret_key = val_data["secret_key"]

    try:
        url = "s3://" + val_data["stanza"]
        bucket, subdir, obj = read_from_s3_uri(url)
        logging.debug("('%s', '%s', '%s')" % (str(bucket), str(subdir), str(obj)))
        if subdir and subdir == obj:
            # monitoring a "sub-directory" within a bucket
            obj = None

            # see if there are any objects that would match that subdir
            all_objs = get_objs_from_bucket(key_id, secret_key, bucket, subdir)
            matches = False
            for o in all_objs:
                if o.startswith(subdir):
                    matches = True
                    break
            if not matches:
                raise Exception, "No objects found inside s3://%s." % "/".join([bucket, subdir])
        else:
            # use_bucket_as_host = False allows for better error checking:
            # AWS tends to return more helpfull error messages
            conn = get_http_connection(key_id, secret_key, bucket, obj, use_bucket_as_host = False)
            resp = conn.getresponse()
            log_response(resp)
            if resp.status / 100 == 3:
                # AWS may send a sometimes when it requires that the bucket
                # is part of the host: retry
                conn = get_http_connection(key_id, secret_key, bucket, obj, use_bucket_as_host = True)
                resp = conn.getresponse()
                log_response(resp)
            if resp.status != 200:
                raise Exception, "Amazon returned HTTP status code %d (%s): %s" % (resp.status, resp.reason, get_amazon_error(resp.read()))

    except Exception, e:
        print_error("Invalid configuration specified: %s" % str(e))
        sys.exit(1)

def test_Checkpointer_verify_item(i, is_compl, total_bytes):
    assert i.is_completed() == is_compl
    assert i.get_total_bytes() == total_bytes

def test_Checkpointer_generate_string(prefix, stanza, item, completed_act, completed_exp, total_bytes_act, total_bytes_exp):
    return "%s stanza=%s item=%s completed-actual=%s completed-expected=%s total_bytes-actual=%d total_bytes-expected=%d" % \
        (prefix, stanza, item, completed_act, completed_exp, total_bytes_act, total_bytes_exp)

def test_Checkpointer_verify(stanza, item, is_compl, total_bytes):
    chk = Checkpointer(".", stanza)
    i = chk.load_item(item)
    try:
        test_Checkpointer_verify_item(i, is_compl, total_bytes)
    except AssertionError, e:
        logging.error(test_Checkpointer_generate_string("ASSERT FAIL:", stanza, \
            item, i.is_completed(), is_compl, i.get_total_bytes(), total_bytes))
        raise
    logging.info(test_Checkpointer_generate_string("Success:", stanza, \
        item, i.is_completed(), is_compl, i.get_total_bytes(), total_bytes))

def test_Checkpointer():
    stanza = "hdfs://my-server:21312/a/path"

    chkpnt_file = get_encoded_csv_file_path(".", stanza)
    try:
        logging.info("Removing '%s'..." % chkpnt_file)
        os.unlink(chkpnt_file)
    except:
        pass

    chk = Checkpointer(".", stanza)

    item1 = "hdfs://my-server:21312/a/path/111"
    i = chk.load_item(item1)
    test_Checkpointer_verify_item(i, False, 0)

    chk.save_item(item1, 111, True)

    test_Checkpointer_verify(stanza, item1, True, 111)

    item2 = "hdfs://my-server:21312/a/path/222"
    chk.save_item(item2, 222, True)

    item3 = "hdfs://my-server:21312/a/path/333"
    chk.save_item(item3, 333)
    chk.sync()

    item4 = "hdfs://my-server:21312/a/path/444"
    chk.save_item(item4, 0)
    chk.sync()
    test_Checkpointer_verify(stanza, item4, False, 0)
    chk.save_item(item4, 444, True)

    # try some odd characters
    item5 = "hdfs://my-server:21312/a/path/\" dslfkj ,,,'\"asd"
    chk.save_item(item5, 555, True)

    test_Checkpointer_verify(stanza, item1, True,  111)
    test_Checkpointer_verify(stanza, item2, True,  222)
    test_Checkpointer_verify(stanza, item3, False, 333)
    test_Checkpointer_verify(stanza, item4, True, 444)
    test_Checkpointer_verify(stanza, item5, True, 555)

def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    sys.exit(2)

def test():
    init_stream()
    send_data("src1", "test 1")
    send_data("src2", "test 2")
    send_done_key("src2")
    send_data("src3", "test 3")
    test_Checkpointer()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        elif sys.argv[1] == "--test":
            test()
        else:
            usage()
    else:
        # just request data from S3
        run()

    sys.exit(0)

