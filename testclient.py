import socket, ssl, json, array, os, hashlib, random, sys

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

def auth_good(sock):
    req = { "covi-request": { "type":"auth", "username":"lev", "password":"lev" } }
    sock.send(json.dumps(req))

def auth_bad(sock):
    req = { "covi-request": { "type":"auth", "username":"wrong", "password":"wrong" } }
    sock.send(json.dumps(req))

def lst(sock):
    sock.send(json.dumps({ "covi-request": { "type":"list" } }))
    res = handle_response(sock.recv())
    if not res:
        return
    """
    try:
        lst = res['list']
    except Exception as e:
        print "%s: %s"(type(e).__name__, str(e))
        return

    for i in lst:
        print i
    """
    print res

def new_dset(sock):
    randf = open('fakedset1.tar.gz', 'rb')
    rsize = os.stat(randf.name).st_size
    arr = array.array('B')
    arr.fromfile(randf, rsize)
    arr = bytearray(arr)
    md5 = hashlib.md5(arr).hexdigest()
    randf.close()

    req = { "covi-request": { "type":"new", "dset":"fakedset1", "len":rsize, "md5":md5 } }
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
        
def rename(sock):
   sock.send(json.dumps({ "covi-request": { "type":"rename", "old":"fakedset1", "new":"fakedset2" } }))
   #sock.send(json.dumps({ "covi-request": { "type":"rename",  "new":"fakedset2" } }))
   res = handle_response(sock.recv())
   if res: print "Rename successful!"

def share(sock):
    sock.send(json.dumps({ "covi-request": { "type":"share", "dset":"fakedset2", "recipient":"bob", "can share":0 } }))
    res = handle_response(sock.recv())
    if res: print "Share successful!"

def share_to_self(sock):
    sock.send(json.dumps({ "covi-request": { "type":"share", "dset":"fakedset2", "recipient":"lev", "can share":0 } }))
    res = handle_response(sock.recv())
    if res: print "Share successful!"


def share_duplicate(sock):
    sock.send(json.dumps({ "covi-request": { "type":"share", "dset":"fakedset2", "recipient":"bob", "can share":0 } }))
    res = sock.recv()
    res = handle_response(res)
    if res: print "Share successful!"

def copy(sock):
    sock.send(json.dumps(
        { "covi-request": { "type":"copy", "source":"fakedset2", "destination":"fakedset3", } }))
    res = sock.recv()
    res = handle_response(res)
    if res: print "Copy successful!"

def copy_shared(sock):
    sock.send(json.dumps(
        { "covi-request": 
            { "type":"copy shared", "source":"fakedset2", "destination":"fakedset4", "owner":"bob" } }))
    res = sock.recv()
    res = handle_response(res)
    if res: print "Copy successful!"


def remove(sock):
    for i in ["fakedset2", "fakedset3"]:
       sock.send(json.dumps({ "covi-request": { "type":"remove", "dset":i } }))
       res = handle_response(sock.recv())
       if res: print "%s removed successfuly!"%(i)

def close(sock):
   sock.send(json.dumps({ "covi-request": { "type":"close" } }))
   
    
def rename_admin(sock, old='fakedset2', new='fakedset3', owner="bob", undo=True):
    for i in xrange(2):
        sock.send(json.dumps({ "covi-request": 
            { "type":"rename admin", "owner":owner, "old":old, "new":new } }))
        res = handle_response(sock.recv())
        if res: print "%s/%s renamed successfuly!"%(owner,old)
        if undo:
            temp = old
            old = new
            new = temp
        else:
            break
    

def remove_admin(sock, dset="fakedset4", owner="lev"):
    sock.send(json.dumps({ "covi-request": 
        { "type":"remove admin", "owner":owner, "dset":dset } }))
    res = handle_response(sock.recv())
    if res: print "%s/%s removed successfuly!"%(owner,dset)
    
    

clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secclisock = ssl.wrap_socket(clientsock, do_handshake_on_connect=False)
secclisock.connect((socket.gethostname(), 14338))
print "Hit enter for SSL handshake"
raw_input()
secclisock.do_handshake()
print "Handshake done"
print "\n\nSending good auth"
auth_good(secclisock)
print "\n\nReply: "
print secclisock.read()

print "\n\nTrying list request"
lst(secclisock)

print "\n\nSending new dset"
new_dset(secclisock)

"""
print "\n\nSending bad auth"
auth_bad(secclisock)
print "\n\nReply: "
print secclisock.read()
"""
print "\n\nRequesting a matrix"
matrix_req(secclisock)
print "\n\nRequesting an invalid matrix"
matrix_req(secclisock, bad=True)
print "\n\nTrying rename"
rename(secclisock)
print "\n\nTrying share"
share(secclisock)
print "\n\nTrying share to self"
share_to_self(secclisock)
print "\n\nTrying duplicate share"
share_duplicate(secclisock)
print "\n\nTrying a good copy"
copy(secclisock)
print "\n\nTrying a good share copy"
copy_shared(secclisock)
print "\n\nRemoving datasets"
remove(secclisock)
print "\n\nTrying rename admin"
rename_admin(secclisock)
print "\n\nTrying remove admin"
remove_admin(secclisock)
"""
print "\n\nClosing connection"
close(secclisock)


secclisock.close()
"""
