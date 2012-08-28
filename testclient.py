import socket, ssl, json, array, os, hashlib, random

def auth_good(sock):
    req = { "covi-request": { "type":"auth", "username":"lev", "password":"lev" } }
    sock.send(json.dumps(req))

def auth_bad(sock):
    req = { "covi-request": { "type":"auth", "username":"wrong", "password":"wrong" } }
    sock.send(json.dumps(req))

def new_dset(sock):
    randf = open('fakedset1.tar.gz', 'rb')
    rsize = os.stat(randf.name).st_size
    arr = array.array('B')
    arr.fromfile(randf, rsize)
    arr = bytearray(arr)
    md5 = hashlib.md5(arr).hexdigest()
    randf.close()

    req = { "covi-request": { "type":"new", "name":"fakedset1", "len":rsize, "md5":md5 } }
    sock.send(json.dumps(req))
    print "Sent req, waiting for reply"
    reply = sock.recv(2048)
    print "Got reply"
    if not handle_response(reply):
        print "Request failed!"
        print reply
        return
    """
    for i in arr:
        sock.send(i)
    """
    sock.send(arr)
    print "Reply:"
    print sock.recv(2048)

def matrix_req(sock, bad=False):
    if bad:
        rand = 'bork bork bork'
    else:
        rand = random.randint(0,4203) 
    print "Requesting matrix %s"%(str(rand))
    req = { "covi-request": { "type":"matrix", "dset":"fakedset1", "number":rand } }
    sock.send(json.dumps(req))
    reply = sock.recv()
    print "Reply: "
    res = handle_response(reply)
    if not res:
        return
    else:
        print res
        length = res["len"]
        md5_hash = res["md5"]
        print "Sending recv ok"
        sock.send(json.dumps({ "covi-request": { "type":"resp ok" } }))
        reply = ''
        print "Starting to recv matrix"
        while len(reply) < length:
            # I know this is slow! This is just for debugging!
            res = sock.recv()
            res = handle_response(res, no_json=True)
            if not res:
                return
            reply += res
        recv_hash = hashlib.md5(res).hexdigest()
        print "Hash of received data:"
        print recv_hash
        print "Hash from server:"
        print md5_hash
        print "Equal? "
        print recv_hash == md5_hash

        

    

def handle_response(reply, no_json=False):
    try:
        reply = json.loads(reply)["covi-response"]
    except:
        if no_json:
            return reply
        else:
            print "JSON fail!"
            sys.exit(1)
    if reply["type"] == "req fail":
        print "request failed!"
        print reply
        return 0
    elif reply["type"] == "req ok":
        return 1
    else:
        return reply

    


    

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
print "No, I'm not"
#new_dset(secclisock)

"""
print "Sending bad auth"
auth_bad(secclisock)
print "Reply: "
print secclisock.read()
"""
print "Requesting a matrix"
matrix_req(secclisock)
print "Requesting an invalid matrix"
matrix_req(secclisock, bad=True)


secclisock.close()
