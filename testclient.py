import socket, ssl, json

def auth_good(sock):
    req = { "covi-request": { "type":"auth", "username":"lev", "password":"lev" } }
    sock.send(json.dumps(req))

def auth_bad(sock):
    req = { "covi-request": { "type":"auth", "username":"wrong", "password":"wrong" } }
    sock.send(json.dumps(req))

clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secclisock = ssl.wrap_socket(clientsock, do_handshake_on_connect=False)
secclisock.connect((socket.gethostname(), 14338))
print "Hit enter for SSL handshake"
raw_input()
secclisock.do_handshake()
print "Handshake done"
print "Sending good auth"
auth_good(secclisock)
print secclisock.read()
print "Reply: "
print "Sending bad auth"
auth_bad(secclisock)
print "Reply: "
print secclisock.read()

secclisock.close()
