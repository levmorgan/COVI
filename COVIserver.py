'''
Created on Aug 1, 2012

@author: lmorgan
'''
import sys, os, re, subprocess
import ssl, sqlite3, threading, socket, json
import signal
from getpass import unix_getpass
from hashlib import sha256
from traceback import print_exc
from getopt import getopt, GetoptError
import hashlib
from OpenSSL import SSL
from shutil import rmtree
from time import sleep

svr_socket_manager = ''

def validated_input(regex, error_message):
    pass

class SvrSocketMgr(threading.Thread):
    '''
    This is the driver class for the server. It sets up the server and manages sockets/threads.
    '''
    svr_socket = ''
    config = {}
    client_sockets = []
    client_threads = []
    conn = ''
    cont = True
    
    errors = {IOError:'IO error', sqlite3.Error:'database error'}
    
    def yn_input(self):
        valid = False
        out = ''
        while not valid:
            print "[Y]/n: ",
            inp = raw_input()
            inp.strip()
            if re.search('[Nn]', inp):
                out = 'n'
                valid = True
                return 'n'
            elif inp == '' or re.search('[Yy]', inp):
                out = 'y'
                valid = True
            else:
                print "Please enter Y or n."
        return out
    
    def dir_input(self):
        valid = False
        while not valid:
            inp = raw_input()
            inp.strip()
                    
            if os.access(inp, os.R_OK):
                valid = True
            else:
                sys.stderr.write("Could not access %s. Check your input and try again.\n"%(inp))
        return inp
            
    
    def pass_input(self):
        password = ''
        verify = ' '
        
        while password != verify:
            password = unix_getpass()
            verify = unix_getpass(prompt='Re-enter password:')
            
            if(password != verify):
                print "Passwords do not match. Please re-enter."
                
            if len(password) == 0:
                print "You must enter a password."
                verify = ' '
        
        return password
            
    def fatal_error(self, function, e):
        print "COVI has encountered an error during %s and cannot continue."%(function)
        print "The error was:"
        print "%s: %s"%((type(e).__name__), str(e))
        print type(e)
        print_exc()
        #raise Exception("Fatal")
        signal.alarm(1)

    def __init__(self, conf_file="COVI_svr.conf", verbose=False):
        '''
        Constructor
        '''
        
        threading.Thread.__init__(self)
        # Try to load server config
        try:
            conf_file = open(conf_file)
        except IOError:
            print "Could not open configuraton file. Configure COVI server?"
            out = self.yn_input()
            if out == 'y':
                try:
                    self.configure_svr()
                    conf_file = open(conf_file)
                except Exception as e:
                    print "COVI has encountered a(n) %s during configuration and cannot continue. "%(type(e).__name__)
                    print "The error was:"
                    print str(e)
                    sys.exit(1)
                
            else:
                print "COVI cannot proceed without the configuration file. Exiting."
                sys.exit(1)
                
        self.config = json.load(conf_file)
        conf_file.close()
        self.config['verbose'] = verbose
        self.v = verbose
            
                
    
    def configure_svr(self):
        try:
            try:
                open('COVIserver.py', 'r')
                
            except IOError:
                print "ERROR: COVI server configuration must be started from the COVI directory."
                sys.exit(1)
            ''' 
            Configure COVI server and write out a configuration file.
            '''      
            if self.config:
                config = self.config
            else:
                home = os.popen('echo ~').read().strip()
                config = {
                          "datadir":"./datasets", "svrport":14338, "afnidir":os.path.join(home, "abin"),
                          "hostname":socket.gethostname(), "cert":None, "pkey":None,
                          }
    
            print "COVI Server Configuration\n\n"
            
            
            print "In which directory should COVI server store its datasets?"
            valid = False
            default = config["datadir"]
            while not valid:
                print "[%s] "%(default),
                inp = raw_input()
                inp.strip()
                
                if inp == '':
                    inp = default
                    if not os.path.exists(inp):
                        os.mkdir(inp)
                        
                if os.access(inp, os.W_OK):
                    valid = True
                else:
                    sys.stderr.write("Could not write to directory %s. Check your input and try again.\n"%(inp))
            config['datadir'] = inp
            
            
            print "Are AFNI/SUMA installed?"
            out = self.yn_input()
            if out == 'y':
                
                print "In which directory is AFNI installed?"
                valid = False
                default = config["afnidir"]
                while not valid:
                    print "[%s] "%(default),
                    inp = raw_input()
                    inp.strip()
                    
                    if inp == '':
                        inp = default
                
                    if os.access(inp, os.W_OK):
                        ok = os.access(os.path.join(inp,'afni'), os.R_OK)
                        ok = ok and os.access(os.path.join(inp,'suma'), os.R_OK)
                        valid = ok
                    else:
                        sys.stderr.write("Could not read AFNI and/or SUMA in directory %s. Check your input and try again.\n"%(inp))
                config['afnidir'] = inp
                
            else:
                print ("COVI server needs AFNI/SUMA installed to create datasets. If you already have COVI datasets"+
                    "and do not want to create any new ones,")
                print "you do not need to install AFNI/SUMA. Disable creation of new datasets?"
                out = self.yn_input()
                if out == 'y':
                    # If user doesn't want it, disable processing pipeline
                    config['afnidir'] = ''
                else:
                    # Otherwise, die
                    print 'Please install AFNI/SUMA and run COVI server configuration again.'
                    sys.exit(1)
            
                
            ### TEST ALL THIS OMGOMGOMG ###
                
            # Database creation
            try:
                conn = sqlite3.connect("COVI_svr.db")
                conn.text_factory = str
            except:
                print "Could not connect to COVI_svr.db. Make sure COVI can access this file."
                sys.exit(1)
            c = conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS users
                        (uid text CONSTRAINT uid_constraint PRIMARY KEY,
                        passhash text,
                        admin integer);''')
            conn.commit()
            c.execute('''CREATE TABLE IF NOT EXISTS dataset
                        (did integer CONSTRAINT did_constraint PRIMARY KEY ASC AUTOINCREMENT,
                        metadata text,
                        path text,
                        owner text CONSTRAINT owner_constraint REFERENCES users (uid) ON DELETE CASCADE ON UPDATE CASCADE)''')
            conn.commit()
            
            create_usr = "INSERT INTO users VALUES (?, ?, ?);"
            
            # User setup
            if conn.execute("SELECT * FROM users WHERE uid='admin'").fetchall():
                print "Administrator already exists, continuing with adding users."
            else:
                print "Administrator Account"
                print "The Administrator can add, change, or remove any dataset administrated by COVI Server."
                print "The user name for the administrator account is admin. Enter a password for the administrator account."
                
                passwd = self.pass_input()
                
                c.execute(create_usr, ('admin', sha256(passwd).hexdigest(), 1))
                conn.commit()
                
                if not os.path.exists(os.path.join(config['datadir'], 'admin')):
                    os.mkdir(os.path.join(config['datadir'],'admin'))
                
                print "Admin account successfully configured"
                
            print "Do you want to add other users at this time?"
            out = self.yn_input()
            
            while out == 'y':
                valid = False
                while not valid:
                    print "Username: ",
                    inp = raw_input()
                    inp.strip()
                    
                    if len(inp) > 0 and len(inp) < 31 and re.match("^[A-Za-z0-9]{3,30}$", inp):
                        user = inp
                        valid = True
                    else:
                        print "Username must be alphanumeric and between 3 and 30 characters."
                    if conn.execute("SELECT * FROM users WHERE uid=?", [user]):
                        print "Cannot add user: user with that username already exists."
                        continue
                    passwd = self.pass_input()
                    try:
                        c.execute(create_usr, (user, sha256(passwd).hexdigest(), 0))
                        conn.commit()
                        if not os.path.exists(os.path.join(config['datadir'], user)):
                            os.mkdir(os.path.join(config['datadir'], user))
                    except sqlite3.IntegrityError:
                        print "Cannot add user: user with that username already exists."
                print "Do you want to add other users at this time?"
                out = self.yn_input()
            

            print "Which port should COVI Server use to listen for connections?"
            print "You will need to make sure this port is open in your firewall."
            print "Choose a port between 1024 and 65536. Default is 14338."
            valid = False
            default = config["svrport"]
            while not valid:
                print "[%s] "%(str(default)),
                inp = raw_input()
                inp.strip()
                # If user accepted default, set their input to the default
                if inp == '':
                    inp = default
                    
                # If not, try to interpret their input
                try:
                    inp = int(inp)
                    if inp <= 65536 and inp >= 1024:
                        try:
                            testsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            testsock.bind((socket.gethostname(), inp))
                            testsock.close()
                        except socket.error as e:
                            print e
                            print type(e)
                            print "Could not bind server to port %i. Choose another port."%(inp)
                            continue
                            
                        valid = True
                except Exception as e:
                    print e
                    pass
                
                if not valid:
                    print "Input must be an integer between 1024 and 65536."
            config['svrport'] = inp
                    
            print "What host name would you like COVI Server to use?"
            print "If you don't have your own SSL certificate, you probably don't need to change this."
            default = socket.gethostname()
            valid = False
            while not valid:
                print "[%s] "%(default),
                inp = raw_input()
                inp.strip()
                if inp == '':
                    inp = default
                try:
                    print (inp, config['svrport'])
                    testsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    testsock.bind((inp, config['svrport']))
                    testsock.close()
                    
                    valid = True
                except socket.gaierror:
                    print "Could not find host name %s. Make sure the host name you're using is associated ",
                    print "with this computer."
                    valid = False # just making sure
            
            config['hostname'] = inp
            
            
                    
            print "COVI Server uses SSL to ensure the security of communications between the server and clients."
            print "To use this protocol, COVI Server needs an SSL certificate. Would you like to generate an SSL ",
            print "certificate now?"
            out = self.yn_input()
            
            ### FINISH CERTIFICATE STUFF ##
            if out == 'y':
                ret = subprocess.call("openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem".split())
                while ret != 0:
                    print "\nCould not generate a certificate. Please try again."
                    ret = subprocess.call("openssl req -new -x509 "+
                                          "-days 365 -nodes -out cert.pem -keyout cert.pem".split())
                cert = 'cert.pem'
                pkey = ''
            else:
                valid = False
                while not valid:
                    print "Which file would you like to use for your certificate?"
                    cert = self.dir_input()
                    
                    print "Is your private key included in the certificate file?"
                    out = self.yn_input()
                    
                    if out == 'n':
                        print "Which file would you like to use for your private key?"
                        pkey = self.dir_input()
                    else:
                        pkey = ''
                        
                    try:
                        svrsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        svrsock.bind((config['hostname'], config['svrport']))
                        svrsock.listen(5)
                        
                        """
                        if pkey:
                            ssl.wrap_socket(svrsock, keyfile=pkey, certfile=cert, server_side=True)
                        else:
                            ssl.wrap_socket(svrsock, certfile=cert, server_side=True)
                        
                        
                        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        ssl.wrap_socket(clientsock, cert_reqs=ssl.CERT_REQUIRED)
                        clientsock.connect((config['hostname'], config['svrport']))
                        svrsock.close()
                        """
                        #TODO: Figure out some way of validating a certificate that is reasonable
                        valid = True
                        
                    except ssl.SSLError:
                        print "There is a problem with either the certificate file or the key file."
                        print "Please specify alternate files."
                        valid = False
                        
            config['cert'] = cert
            config['pkey'] = pkey
                
                # Test input values
                
                    
            config['COVIdir'] = os.getcwd()
            
            conf_file = open('COVI_svr.conf', 'w')
            json.dump(config, conf_file)
            conf_file.close()
            
            print "Configuration file was written successfully! You can now start using server by relaunching it."
        except Exception as e:
            self.fatal_error('configuration', e)
            return
            
    def run(self):
        # Start the server
        print "COVI Server is starting"
        
        try:
            self.conn = sqlite3.connect(os.path.join(self.config['COVIdir'],"COVI_svr.db"), )
        except sqlite3.Error as e:
            self.fatal_error('startup', e)
            return
        print "Connected to database successfully"
            
        # Pipeline stuff is TBA
        
        # Prepare for incoming connections
        if self.v: print "Opening server socket"
        for i in xrange(3):
            try:
                svr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                svr_socket.bind((self.config['hostname'], self.config['svrport']))
                svr_socket.listen(5)
                self.svr_socket = svr_socket
                success = True
                break
            except socket.error as e:
                if self.v: print "Opening socket failed"
                svr_socket.close()
                success = False
                
        if not success:
            self.fatal_error("opening server port", e)
            return
            
        print "COVI server is now up and accepting connections"
        if self.v: print "Beginning main loop"
        while self.cont:
            client_socket, address = svr_socket.accept()
            if self.v: print "Accepting connection"
            del address
            self.client_threads.append(ClientThread(client_socket,
                                       self.config
                                       ))
            #self.client_threads[-1]
            try:
                self.client_threads[-1].start()
            except Exception as e:
                err_str = "Thread %s experienced a fatal error %s"%(
                                              self.client_threads[-1].name,
                                              str(e)
                                              )
                if self.v: print err_str
                self.client_threads[-1].req_fail("The thread handling your requests experienced a fatal error. "
                                                 +"Please reconnect.")
                
                
                
            if self.v: print "Thread dispatched"
            #self.client_sockets.append(client_socket)
    
    def clean_up(self):
        self.cont = False
        for thread in self.client_threads:
            thread.clean_up()
            
    
    def test_sock_client(self):
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secclisock = ssl.wrap_socket(clientsock)
        secclisock.connect((self.config['hostname'], self.config['svrport']))
        inp = raw_input()
        secclisock.send(inp)
        secclisock.close()
                
    
    def test_sock(self):
        svrsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        svrsock.bind((self.config['hostname'], self.config['svrport']))
        svrsock.listen(5)
        #clithread = multiprocessing.Process(target=self.test_sock_client())
        print "Dudes"
        sock, address = svrsock.accept()
        del address
        if 'pkey' in self.config:
            secsock = ssl.wrap_socket(sock, keyfile=self.config['pkey'], certfile=self.config['cert'], server_side=True)
        else:
            secsock = ssl.wrap_socket(sock, certfile=self.config['cert'], server_side=True)
        outp = secsock.read()
        print outp
        
        
        secsock.close()
        svrsock.close()
        
class CThreadException(Exception):
    def __init__(self, message=''):
        self.message = message
        
class ClientThread(threading.Thread):
    '''
    The class that deals with requests from clients.
    '''
    
    client_socket = ''
    dispatch = {}
    config = {}
    permissions = {}
    cont = True
    
    def __init__(self, client_socket, config):
        threading.Thread.__init__(self)
        self.v = config['verbose']
        self.client_socket = client_socket
        self.dispatch = {
                            "auth":self.auth,
                            "new":self.new,
                            None:"""
                            
                            "matrix":self.matrix,
                            "resubmit":self.resubmit,
                            "rename":self.rename,
                            "delete":self.delete,
                            "keepalive":self.keepalive,
                            "close":self.close,"""
                         }
        self.config = config
        self.permissions = ''
        
    def try_recv(self, bufsize=2048):
        try:
            data = self.client_socket.recv(2048)
            if not data:
                raise CThreadException("Connection was terminated")
            return data
        except ssl.socket_error:
            if self.v: print "Thread %s timed out"%(self.name)
            self.req_fail('the connection timed out')
        except socket.error as e:
            if self.v: print "Thread %s socket error while receiving: %s"%(self.name, str(e))
            self.req_fail('there was a connection error: %s'%(str(e)))
            
        
        
    def clean_up(self):
        # TODO: Make cleanup method for threads
        self.cont = False
    
    def run(self):
        if self.v: print "Thread %s wrapping socket"%self.name
        if 'pkey' in self.config:
            self.client_socket = ssl.wrap_socket(
                                                self.client_socket, 
                                                keyfile=self.config['pkey'], 
                                                certfile=self.config['cert'], 
                                                server_side=True,
                                                do_handshake_on_connect=False
                                                )
        else:
            self.client_socket = ssl.wrap_socket(
                                                self.client_socket, 
                                                certfile=self.config['cert'], 
                                                server_side=True,
                                                do_handshake_on_connect=False
                                                )
        
        # Set a timeout on the socket, in case the connection dies
        #self.client_socket.settimeout(10.0)
        #TODO: Re-enable timeout before handshake 
        
        
        if self.v: print "Thread %s blocking on SSL handshake"%self.name
        try:
            self.client_socket.do_handshake()
        except ssl.socket_error:
            if self.v: print "Thread %s handshake timed out"%self.name
            self.client_socket.close()
            return
        if self.v: print "Thread %s unblocking from SSL handshake"%self.name
        
        # Every ten seconds, give the program a chance to close
        self.client_socket.settimeout(10.0)
        timeouts = 0
        while self.cont:
            # Decode encoded JSON request and decide what to do with it
            
            if self.v: print "Thread %s blocking on socket"%(self.name)
            try:
                timeouts = 0
                enc_req = self.client_socket.recv()
            
            except ssl.socket_error:
                timeouts += 1
                # If there has been no communication for 5 minutes, die
                if timeouts >= 60:
                    if self.v: print "Thread %s timed out"%(self.name)
                    self.client_socket.close()
                    return
                else:
                    continue
            
            if not enc_req:
                if self.v: print "Thread %s connection is dead, dying"%(self.name)
                self.client_socket.close()
                return
            
            if self.v: print "Thread %s Got data, looks like:\n%s"%(self.name, str(enc_req))
            try:
                if self.v: print "Thread %s trying to decode data"%(self.name)
                req = json.loads(enc_req)
                if self.v: print "Thread %s request is: %s"%(self.name, str(req))
            except:
                # Got bad data. Ignore it, keep looping
                self.req_fail("it was not a valid JSON request")
                if self.v: print "Thread %s failed to decode data"%(self.name)
                continue
            try:
                if self.v: print "Thread %s trying to handle request"%self.name
                req = req['covi-request']
                self.dispatch[req['type']](req)
            except KeyError as e:
                # Bad message. Ignore it.
                self.req_fail("it was not a valid COVI request")
                if self.v: print "Thread %s error getting message type: %s"%(self.name, e.message)
                continue
            # Once we're done processing the input, close when the program closes
        
    def req_ok(self):
        self.client_socket.send('{ "covi-response": { "type":"req ok" } }')
        
    def req_fail(self, message, prefix=True):
        if prefix:
            self.client_socket.send('{ "covi-response": { "type":"req fail",'+
                                    ' "message":"Your request could not be executed because %s." } }'%(message))
        else:
            self.client_socket.send('{ "covi-response": { "type":"req fail",'+
                                    ' "message":"%s" } }'%(message))
        
    def auth(self, req):
        # handle authentication
        
        if self.v: 
            print "Thread %s beginning authentication handling"%(self.name)
        try:
            user = req['username'] 
            passwd = req['password']
            passwd = sha256(passwd).hexdigest()
        
        except KeyError:
            # Bad request, ignore it
            if self.v: print "Thread %s could not find valid uid and password"%(self.name)
            self.req_fail("it was an auth request but did not contain a valid username and password")
            return
        
        # Fetch permissions
        try:    
            if self.v: print "Thread %s trying to fetch auth info from database"%(self.name)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            res = conn.execute('SELECT * FROM users WHERE uid=? and passhash=?', 
                                            [user, passwd]).fetchone()
            if res and len(res) == 3:
                if self.v: print "Thread %s auth ok"%(self.name)
                self.permissions = {'uid':res[0], 'admin':res[2]}
                self.req_ok()
            else:
                if self.v: print "Thread %s auth failed"%(self.name)
                self.req_fail("Username or password could not be authenticated", prefix=False)
                return
                
        
        except Exception as e:
            if self.v: print "Thread %s auth failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            return
            
    def new(self, req):
        
        if self.v: print "Thread %s trying to get dset metadata"%(self.name)
        try:
            name = req['name']
            length = int(req['len'])
            md5 = req['md5']
        except:
            if self.v: print "Thread %s invalid data in new dset request"%(self.name)
            self.req_fail("it is not a valid new dataset request")
            return
        
        try:
            if self.v: print "Thread %s creating directories"%(self.name)
            try:
                dset_dir = os.path.join(
                                   self.config['COVIdir'],
                                   self.permissions['uid'],
                                   name
                                   )
                os.makedirs(dset_dir)
                dset_arch = open(os.path.join(dset_dir,'%s.tar.gz'%(name)), 'wb')
                 
            except Exception as e:
                if self.v: print "Thread %s failed to create file/dir for new dset"%(self.name)
                self.req_fail('your dataset could not be written to disk. Make sure the dataset name'+
                              'does not include any illegal characters')
                raise CThreadException()
                
            if self.v: print "Thread %s sending metadata receipt OK"%(self.name)
            try:
                self.req_ok()
            except Exception as e:
                if self.v: print "Thread %s encountered unrecoverable exception"%(self.name, str(e))
                raise CThreadException()
                
                
            
            arr = []
            bytes_recvd = 0
            
            try:
                if self.v: print "Thread %s trying to start receiving data"%(self.name)
                # This may not work
                while bytes_recvd < length:
                    temp = self.try_recv()
                    arr.append(temp)
                    bytes_recvd += len(arr[-1])
                    if self.v: print "Thread %s recv'd %i bytes_recvd so far"%(self.name, bytes_recvd)
                data = ''.join(arr)
            except ssl.socket_error:
                if self.v: print "Thread %s timed out"%(self.name)
                self.req_fail('the connection timed out while transferring the dataset.')
                raise CThreadException()
            except CThreadException as e:
                if self.v: print "Thread %s connection broken"%(self.name)
                raise
    
                    
            if self.v: print "Thread %s checking data integrity "%(self.name)
            svr_md5 = hashlib.md5(data).hexdigest()
            if svr_md5 != md5:
                self.req_fail('the data received was different from the data sent due to a transmission error',)
                raise CThreadException()
                
            if self.v: print "Thread %s writing archive "%(self.name)
            dset_arch.write(data)
            dset_arch.close()
            self.req_ok()
        except Exception as e:
            if self.v: print "Thread %s cleaning up directories "%(self.name)
            if os.path.exists(dset_dir):
                try:
                    rmtree(dset_dir)
                except OSError:
                    #TODO: Notify an administrator about this
                    pass
            if type(e) != CThreadException:
                if self.v: print "Thread %s caught non-CThread Exception; passing it on"%(self.name)
                raise
            

def close_gracefully(signal, frame):
    print "COVI server is terminating"
    svr_socket_manager.clean_up()
    sys.exit(0)
                    
if __name__ == '__main__':
    # Process arguments
    try:
        optlist, args = getopt(sys.argv[1:], 'v', ["help", "reconfigure", "verbose"])
    except GetoptError as e:
        print str(e)
        print "Usage: python COVIserver.py [-v] [--help] [--reconfigure] [--verbose]"
        sys.exit(2)
    
    if "--help" in sys.argv:
        print "Usage: python COVIserver.py [--help] [--reconfigure]"
        sys.exit(2)
    
    verbose = False
    
    for opt in optlist:
        if opt[0] == '--reconfigure':
            SvrSocketMgr().configure_svr()
            sys.exit(0)
        
        if opt[0] == '--verbose' or opt[0] == '-v':
            verbose = True
        
    # Start server
    svr_socket_manager = SvrSocketMgr(verbose=verbose)
    #svr_socket_manager.run()
    #svr_socket_manager.test_sock()
    svr_socket_manager.setDaemon(True)
    try:
        svr_socket_manager.start()
    except Exception as e:
        print_exc()
        print "Exiting"
        sys.exit(1)
        
    
    #set up signal handling
    
    signal.signal(signal.SIGINT, close_gracefully)
    signal.signal(signal.SIGTERM, close_gracefully)
    signal.signal(signal.SIGQUIT, close_gracefully)
    #signal.signal(signal.SIGKILL, close_gracefully)
    
    signal.pause()