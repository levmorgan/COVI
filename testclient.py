import socket, ssl, json, array, os, hashlib

def auth_good(sock):
    req = { "covi-request": { "type":"auth", "username":"lev", "password":"lev" } }
    sock.send(json.dumps(req))

def auth_bad(sock):
    req = { "covi-request": { "type":"auth", "username":"wrong", "password":"wrong" } }
    sock.send(json.dumps(req))

def new_dset(sock):
    randf = open('randfile.tar.gz', 'rb')
    rsize = os.stat(randf.name).st_size
    arr = array.array('B')
    arr.fromfile(randf, rsize)
    arr = bytearray(arr)
    md5 = hashlib.md5(arr).hexdigest()
    randf.close()

    req = { "covi-request": { "type":"new", "name":"dset1", "len":rsize, "md5":md5 } }
    sock.send(json.dumps(req))
    print "Sent req, waiting for reply"
    reply = sock.recv(2048)
    print "Got reply"
    if not handle_response(reply):
        return
    """
    for i in arr:
        sock.send(i)
    """
    sock.send(arr)
    print "Reply:"
    print sock.recv(2048)

def handle_response(reply):
    try:
        reply = json.loads(reply)["covi-response"]
    except:
        print "JSON fail!"
        sys.exit(1)
    if reply["type"] == "req fail":
        print "request failed!"
        print reply
        return 0
    elif reply["type"] == "req ok":
        return 1

    


    

clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secclisock = ssl.wrap_socket(clientsock, do_handshake_on_connect=False)
secclisock.connect((socket.gethostname(), 14338))
print "Hit enter for SSL handshake"
raw_input()
secclisock.do_handshake()
print "Handshake done"
print "Sending good auth"
auth_good(secclisock)
print "Reply: "
print secclisock.read()

print "Sending new dset"
new_dset(secclisock)

"""
print "Sending bad auth"
auth_bad(secclisock)
print "Reply: "
print secclisock.read()
"""


secclisock.close()
