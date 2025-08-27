import os
import sqlite3
import subprocess
import pickle
import yaml
import tempfile
import requests
import hashlib
import random
import socket
import urllib.request
import xml.etree.ElementTree as ET
import base64
import hmac

def v1_sql_injection(username):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
    cur.execute("INSERT INTO users (name) VALUES ('alice')")
    query = "SELECT id FROM users WHERE name = '%s';" % username
    cur.execute(query)
    return cur.fetchall()

def v2_command_injection(cmd):
    os.system("echo starting && " + cmd)

def v3_eval_input(expr):
    return eval(expr)

def v4_exec_input(code):
    exec(code)

def v5_unpickle(data):
    return pickle.loads(data)

def v6_yaml_load(data):
    return yaml.load(data)

def v7_insecure_mktemp():
    name = tempfile.mktemp(prefix="tmp_")
    f = open(name, "w")
    f.write("tempdata")
    f.close()
    return name

def v8_disable_tls(url):
    return requests.get(url, verify=False).content

def v9_hardcoded_credentials():
    return {"user": "admin", "pass": "SuperSecretHardcodedPass!"}

def v10_hardcoded_key_sign(data):
    key = b"hardcoded_signing_key_please_change"
    return hmac.new(key, data if isinstance(data, bytes) else str(data).encode(), hashlib.sha256).hexdigest()

def v11_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def v12_predictable_token():
    return str(int(random.random() * 10**9))

def v13_store_cleartext(path, pwd):
    f = open(path, "w")
    f.write("password=" + pwd + "\n")
    f.close()
    return path

def v14_log_secret(secret):
    print("DEBUG SECRET:", secret)

def v15_path_traversal_read(filename):
    return open(filename, "r").read()

def v16_chmod_world_writable(path):
    f = open(path, "w")
    f.write("data")
    f.close()
    os.chmod(path, 0o777)
    return path

def v17_save_uploaded(filename, data):
    f = open(filename, "wb")
    f.write(data)
    f.close()
    return filename

def v18_open_redirect(target):
    return "Location: " + target

def v19_plain_http_send(host, port, secret):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(secret.encode())
    s.close()
    return True

def v20_ssrf_fetch(url):
    return requests.get(url).text

def v21_subprocess_shell(cmd):
    subprocess.Popen(cmd, shell=True)

def v22_insecure_xml_parse(xmlstr):
    return ET.fromstring(xmlstr)

def v23_download_and_exec(url):
    code = urllib.request.urlopen(url).read()
    exec(code)

def v24_large_allocation(n):
    return [0] * int(n)

def v25_insecure_socket_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    conn, _ = s.accept()
    data = conn.recv(4096)
    conn.close()
    s.close()
    return data

def v26_pickle_dump(obj, path):
    f = open(path, "wb")
    f.write(pickle.dumps(obj))
    f.close()
    return path

def v27_os_remove_user_path(path):
    os.system("rm -rf " + path)

def v28_format_sql(user):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE t (c TEXT);")
    cur.execute("INSERT INTO t (c) VALUES ('x');")
    q = "INSERT INTO t (c) VALUES ('%s');" % user
    cur.execute(q)
    return True

def v29_jwt_none(payload):
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=')
    body = base64.urlsafe_b64encode(str(payload).encode()).rstrip(b'=')
    return header.decode() + "." + body.decode() + "."

def v30_unvalidated_redirect_server(redirect_url):
    class R:
        def handle(self):
            return ("HTTP/1.1 302 Found\r\nLocation: " + redirect_url + "\r\n\r\n").encode()
    return R()

if __name__ == "__main__":
    print("Vulnerable module loaded. Do not execute functions on production systems.")
