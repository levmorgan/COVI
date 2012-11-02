'''
Created on Aug 1, 2012

@author: lmorgan
'''
#TODO: COVI Server must be run from the directory it's in. That's stupid. Make all file refs WRT COVI_dir
import sys, os, re, subprocess, ssl, hashlib, tarfile
import sqlite3, threading, socket, json, signal, shutil
from getpass import unix_getpass
from hashlib import sha256
from traceback import print_exc
from getopt import getopt, GetoptError
from collections import defaultdict
#from time import sleep
from multiprocessing import Process

svr_socket_manager = ''

def validated_input(regex, error_message):
    pass

def full_name(obj):
    return obj.__class__.__name__

class SvrSocketMgr(threading.Thread):
    """
    This is the driver class for the server. It sets up the server and manages sockets/threads.
    """
    svr_socket = ''
    config = {}
    client_sockets = []
    client_threads = []
    conn = ''
    cont = True
    
    def yn_input(self, default='Y'):
        valid = False
        out = ''
        while not valid:
            if re.match('[Yy]',default):
                defout = 'y'
                print "[Y]/n: ",
            elif re.match('[Nn]',default):
                defout = 'n'
                print "y/[N]: ",
            elif default == '':
                defout = ''
                print 'y/n: ',
            
            inp = raw_input()
            inp.strip()
            if re.search('[Nn]', inp):
                out = 'n'
                valid = True
                return 'n'
            elif re.search('[Yy]', inp):
                out = 'y'
                valid = True
            elif inp == '' and defout:
                out = defout
                valid = True
                
            else:
                print "Please enter Y or n."
        return out
    
    def dir_input(self, default=''):
        valid = False
        while not valid:
            if default:
                print "[%s]: "%default,
            inp = raw_input()
            inp.strip()
            
            if default and not inp:
                inp = default        
            
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
        print "%s: %s"%(full_name(e), str(e))
        print full_name(e)
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
            print "Could not open configuration file. Configure COVI server?"
            out = self.yn_input()
            if out == 'y':
                try:
                    self.configure_svr()
                    conf_file = open(conf_file)
                # TODO: Catching "Exception" here
                except Exception as e:
                    print ("COVI has encountered a(n) %s exception"%(full_name(e)) + 
                           " during configuration and cannot continue.")
                    print "The error was:"
                    print str(e)
                    sys.exit(1)
                
            else:
                print "COVI can't proceed without the configuration file. Exiting."
                sys.exit(1)
                
        self.config = json.load(conf_file)
        conf_file.close()
        self.config['verbose'] = verbose
        self.v = verbose
            
                
    
    def configure_svr(self):
        # TODO: Break this up into different methods, so e.g. users could be added without reconfiguring the whole server
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
                      "data_dir":"datasets", "svrport":14338, "afni_dir":os.path.join(home, "abin"),
                      "hostname":socket.gethostname(), "cert":'', "pkey":'',
                      }

        print "COVI Server Configuration\n\n"
        
        
        print "In which directory should COVI server store its datasets?"
        valid = False
        default = config["data_dir"]
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
        config['data_dir'] = inp
        
        
        print "Are AFNI/SUMA installed?"
        out = self.yn_input()
        if out == 'y':
            
            print "In which directory is AFNI installed?"
            valid = False
            default = config["afni_dir"]
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
            config['afni_dir'] = inp
            
        else:
            print ("COVI server needs AFNI/SUMA installed to create datasets. If you already have COVI datasets"+
                "and do not want to create any new ones,")
            print "you do not need to install AFNI/SUMA. Disable creation of new datasets?"
            out = self.yn_input()
            if out == 'y':
                # If user doesn't want it, disable processing pipeline
                config['afni_dir'] = ''
            else:
                # Otherwise, die
                print 'Please install AFNI/SUMA and run COVI server configuration again.'
                sys.exit(1)
        
            
        ### TEST ALL THIS OMGOMGOMG ###
            
        # Database creation
        try:
            conn = sqlite3.connect("COVI_svr.db")
            conn.text_factory = str
        except sqlite3.OperationalError:
            print "Could not connect to COVI_svr.db. Make sure COVI can access this file."
            sys.exit(1)
        
    
        c = conn.cursor()
        
        valid = False
        # FIXME: Make exception handler respond intelligently to duplicate tables.
        # FIXME: Right now it would fail if users was a duplicate, or just repeat the previous error.
        while not valid:
            try:
                c.execute('''CREATE TABLE users
                            (uid text CONSTRAINT uid_constraint PRIMARY KEY,
                            passhash text,
                            admin integer);''')
                
                valid = True
            except sqlite3.OperationalError as e:
                tab_name = re.sub(r'^table (.*) already exists$', '\\1', e.message)
                if tab_name != e.message: # If the message matches the regex
                    print "COVI has encountered an error during configuration:"
                    print e.message
                    print "If you keep the table, it may leave the database in an inconsistent state."
                    print "Delete and re-create table? Any data in the table will be lost."
                    inp = self.yn_input(default='n')
                    if inp == 'y':
                        c.execute("DROP TABLE users;") 
                        conn.commit()
                    else:
                        valid = True
        valid = False
        while not valid:
            try:
                c.execute('''CREATE TABLE shared_files 
                            (owner REFERENCES users (uid) ON DELETE CASCADE,
                            recipient REFERENCES users (uid) ON DELETE CASCADE,
                            dataset TEXT,'''
                            #can_write INTEGER,
                            +'''can_share INTEGER,
                            is_request INTEGER);''')
                conn.commit()

                valid = True

            except sqlite3.OperationalError as e:
                tab_name = re.sub(r'^table (.*) already exists$', '\\1', e.message)
                if tab_name != e.message: # If the message matches the regex
                    print "COVI has encountered an error during configuration:"
                    print e.message
                    print "If you keep the table, it may leave the database in an inconsistent state."
                    print "Delete and re-create table? Any data in the table will be lost."
                    inp = self.yn_input(default='n')
                    if inp == 'y':
                        c.execute("DROP TABLE shared_files;") 
                        conn.commit()
                    else:
                        valid = True


        """
        c.execute('''CREATE TABLE IF NOT EXISTS dataset
                    (did integer CONSTRAINT did_constraint PRIMARY KEY ASC AUTOINCREMENT,
                    metadata text,
                    path text,
                    owner text CONSTRAINT owner_constraint REFERENCES users (uid) ON DELETE CASCADE ON UPDATE CASCADE)''')
        conn.commit()
        """
        
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
            
            if not os.path.exists(os.path.join(config['data_dir'], 'admin')):
                os.mkdir(os.path.join(config['data_dir'],'admin'))
            
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
                if conn.execute("SELECT * FROM users WHERE uid=?", [user]).fetchall():
                    print "Cannot add user: user with that username already exists."
                    continue
                passwd = self.pass_input()
                try:
                    c.execute(create_usr, (user, sha256(passwd).hexdigest(), 0))
                    conn.commit()
                    if not os.path.exists(os.path.join(config['data_dir'], user)):
                        os.mkdir(os.path.join(config['data_dir'], user))
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
                        print full_name(e)
                        print "Could not bind server to port %i. Choose another port."%(inp)
                        continue
                        
                    valid = True
            # If we didn't get an int, just pass
            except ValueError as e:
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
        print "To use this protocol, COVI Server needs an SSL certificate. Would you like to generate an SSL",
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
                cert = self.dir_input(default=config['cert'])
                
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
            
                
        config['COVI_dir'] = os.getcwd()
        
        conf_file = open('COVI_svr.conf', 'w')
        json.dump(config, conf_file)
        conf_file.close()
        
        print "Configuration file was written successfully! You can now start using server by relaunching it."
            
    def run(self):
        # Start the server
        print "COVI Server is starting"
        if self.v: print "Startup: Checking config file."
        keys = [u'pkey', u'data_dir', u'verbose', u'hostname', 
                u'svrport', u'afni_dir', u'cert', u'COVI_dir']
        try:
            for i in keys:
                if not i in self.config:
                    raise ValueError("Configuration file is missing required entry %s.", i)
        except ValueError as e:
            self.fatal_error("run", e)
        
        
        try:
            self.conn = sqlite3.connect(os.path.join(self.config['COVI_dir'],"COVI_svr.db"), )
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
            ## Does this actually catch anything?
            except Exception as e:
                err_str = "Thread %s: run: experienced a fatal error %s"%(
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
        
class ClientThread(Process):
#class ClientThread(Process):
    '''
    The class that deals with requests from clients.
    '''
    
    client_socket = ''
    dispatch = {}
    config = {}
    permissions = {}
    cont = True
    
    def __init__(self, client_socket, config):
        Process.__init__(self)
        self.v = config['verbose']
        self.client_socket = client_socket
        self.dispatch = {
                            "auth":self.auth,
                            "new":self.new,
                            "matrix":self.matrix,
                            "shared matrix":self.matrix,
                            "close":self.close,
                            "rename":self.rename,
                            "remove":self.remove,
                            "keepalive":self.keepalive,
                            "list":self.list,
                            "share":self.share,
                            "copy":self.copy,
                            "copy shared":self.copy,
                            "remove shared":self.remove_shared,
                            
                            None:"""
                            
                            
                            "resubmit":self.resubmit,
                            """
                         }
        self.config = config
        self.permissions = {}
    
    def dset_path(self, dset, owner=''):
        if owner:
            return os.path.join(
                              self.config['COVI_dir'],
                              self.config['data_dir'],
                              self.leaf(owner),
                              self.leaf(dset)
                              )
        else:
            return os.path.join(self.permissions["user_dir"],
                                self.leaf(dset))
            
    def shared_dset_path(self, owner, dset):
        return os.path.join(
                            self.config['data_dir'],
                            owner,
                            self.leaf(dset)
                            )
        
    def try_recv(self, bufsize=2048):
        try:
            data = self.client_socket.recv(2048)
            if not data:
                raise CThreadException("connection was terminated")
            return data
        except ssl.socket_error:
            if self.v: print "Thread %s: timed out"%(self.name)
            self.req_fail('the connection timed out')
            raise CThreadException("connection timed out")
        except socket.error as e:
            if self.v: 
                print "Thread %s socket error while receiving: %s"%(self.name, str(e))
            self.req_fail('there was a connection error: %s'%(str(e)))
            raise CThreadException("connection error")
            
        
    def leaf(self, path):
        return os.path.basename(path)
    
    def check_writable(self, dset, owner=''):
        '''
        Return True if directory exists and is writable
        '''
        if owner:
            return os.access(
                      self.dset_path(dset, owner),
                      os.W_OK
                     )
        else:
            return os.access(
                      self.dset_path(dset),
                      os.W_OK
                     )
        
    
    def check_shared(self, owner, dset):
        '''
        Checks if a dataset, "dset", has been shared by "owner" to 
        the current user
        Returns either the approprite record, a fabricated record (for admin), 
        or an empty list
        '''
        if self.permissions['admin']:
            # If the database exists, the admin can access it
            if self.check_writable(dset, owner):
                return (owner, self.permissions['uid'], dset, 1, 0)
            else:
                #TODO: Should this raise an exception?
                return False
        try:    
            if self.v: 
                print "Thread %s: check_shared: checking if user %s shared %s"%(
                    self.name, owner, dset),
                print "with %s"%(self.permissions["uid"])
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            res = conn.execute(
                'SELECT * FROM shared_files WHERE owner=? AND recipient=? AND dataset=?',
                 [owner, self.permissions['uid'], dset]).fetchall()
            
            if self.v: print "Thread %s: check shared: res is:\n %s"%(self.name, str(res))
            
            return res
            
        except sqlite3.Error as e:
            if self.v: print "Thread %s: check_shared: check failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            raise
    
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
                #TODO: Re-enable timeouts when debugging is over
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
            except ValueError:
                # Got bad data. Ignore it, keep looping
                self.req_fail("it was not a valid request")
                if self.v: print "Thread %s failed to decode data"%(self.name)
                continue
            try:
                if self.v: print "Thread %s trying to handle request"%self.name
                req = req['covi-request']
                if not self.permissions:
                    if req['type'] != 'auth':
                        self.req_fail("the client is not authenticated yet")
                if req["type"] in self.dispatch:
                    self.dispatch[req['type']](req)
                else:
                    # Bad message. Ignore it.
                    self.req_fail("COVI does not know how to handle a %s request"%str(req['type']))
                    #if self.v: print "Thread %s error handling message of type: %s"%(self.name, str(e))
                    if self.v: print "Thread %s error: COVI does not know how to handle a %s request"%(self.name,
                                                                                                str(req['type']))
            # TODO: Catching "Exception" here
            except Exception as e:
                if self.v: 
                    print "Thread %s encountered an uncaught %s exception while processing a %s request: %s. "%(
                                                                        self.name, full_name(e), req['type'], str(e))
                self.req_fail("there was an uncaught %s error while processing the %s request: %s "
                              %(full_name(e), req['type'], str(e)))
                continue
            # Once we're done processing the input, close when the program closes
        
    def req_ok(self):
        '''
        Sends a message to the client that their request succeeded.
        '''
        self.client_socket.send('{ "covi-response": { "type":"req ok" } }')
        
    def req_fail(self, message, prefix=True):
        '''
        Send a customizable message to the client informing them that their request failed.
        If prefix is True, 'message' is inserted into a boilerplate error message.
        '''
        if prefix:
            self.client_socket.send(('{ "covi-response": { "type":"req fail",'+
                                    ' "message":"Your request could not be executed because %s. '+
                                    'Try your request again." } }')%(message))
        else:
            self.client_socket.send('{ "covi-response": { "type":"req fail",'+
                                    ' "message":"%s" } }'%(message))
            
    def handle_env_error(self, e, method):
        '''
        Give the necessary server output for various kinds of environment errors
        Takes e, an EnvironmentError, and method, a string describing the method where
        the error originated
        '''
        if e[0] == 39:
            if self.v: print "Thread %s: %s: dataset already exists: %s"%(self.name, method, str(e))
            self.req_fail("a dataset with that name already exists")
        elif e[0] == 2:
            if self.v: print "Thread %s: %s: dataset does not exist"%(self.name, method)
            self.req_fail("there is no dataset with that name")
        elif e[0] == 17:
            if self.v: print "Thread %s: %s: destination dataset already exists"%(self.name, method)
            self.req_fail("the destination dataset already exists")
        else:
            if self.v: print "Thread %s: %s: failed to read or write file: %s"%(self.name, method, str(e))
            self.req_fail("COVI could not perform the necessary reads "+
                          "or writes to the file system: %s"%(str(e)))
        return
    
    def handle_key_error(self, e, method):
        if self.v: 
            print "Thread %s: %s: invalid data in request: %s: %s"%(
                self.name, method, full_name(e), str(e))
        self.req_fail("it was missing required fields "+
                      "for a %s request: %s"%(method, str(e)))
        
    def auth(self, req):
        '''
        Checks to see if the 'username' and 'password' fields of req match any of the users
        in the database. If they do, load their permissions.
        '''
        # TODO: Add an exception for administrators
        if self.v: 
            print "Thread %s: auth: beginning authentication handling"%(self.name)
        try:
            user = req['username'] 
            passwd = req['password']
            passwd = sha256(passwd).hexdigest()
        
        except KeyError:
            # Bad request, ignore it
            if self.v: print "Thread %s: auth: could not find valid uid and password"%(self.name)
            self.req_fail("it was an auth request but did not contain a valid username and password")
            return
        
        # Fetch permissions
        try:    
            if self.v: print "Thread %s: auth: trying to fetch auth info from database"%(self.name)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            res = conn.execute('SELECT * FROM users WHERE uid=? and passhash=?', 
                                            [user, passwd]).fetchone()
            if res and len(res) == 3:
                if self.v: print "Thread %s: auth: auth ok"%(self.name)
                self.permissions = {'uid':res[0], 'admin':res[2]}
                user_dir = os.path.join(
                                   self.config['COVI_dir'],
                                   self.config['data_dir'],
                                   self.permissions['uid']
                                   )
                self.permissions['user_dir'] = user_dir
                self.req_ok()
            else:
                if self.v: print "Thread %s: auth: auth failed"%(self.name)
                self.req_fail("Username or password could not be authenticated", prefix=False)
                return
                
        
        except Exception as e:
            if self.v: print "Thread %s: auth: auth failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            return
            
    def new(self, req):
        method = 'new'
        if self.v: print "Thread %s: new dset: trying to get dset metadata"%(self.name)
        try:
            dset = self.leaf(req['dset'])
            length = int(req['len'])
            md5 = req['md5']
            # FIXME: Dataset names must be alphanumeric+_-.
        except KeyError as e:
            self.handle_key_error(e, method)
            return
        
        dset_dir = self.dset_path(dset)
        
        try:
            if self.v: print "Thread %s: new dset: creating directories"%(self.name)
            try:
                if os.path.exists(dset_dir):
                    if self.v: print "Thread %s: new dset: dataset already exists"%(self.name)
                    self.req_fail("there is already a dataset with that name. If you want to resubmit it, "+
                                  "use the resubmit function")
                    return
                    
                print dset_dir
                os.makedirs(dset_dir)
                dset_arch = open(os.path.join(dset_dir,'%s.tar.gz'%(dset)), 'wb')
                 
            except (OSError, IOError) as e:
                '''if self.v: print "Thread %s: new dset: failed to create file/dir for new dset%s: %s"%(self.name, 
                                                                                              full_name(e), 
                                                                                              str(e))
                self.req_fail('your dataset could not be written to disk')'''
                self.handle_env_error(e, method)
                raise CThreadException()
                
            if self.v: print "Thread %s: new dset: sending metadata receipt OK"%(self.name)
            try:
                self.req_ok()
            except Exception as e:
                if self.v: print "Thread %s: new dset: encountered unrecoverable exception"%(self.name, str(e))
                raise CThreadException()
                
                
            
            arr = []
            bytes_recvd = 0
            
            try:
                arch_hash = hashlib.md5()
                if self.v: print "Thread %s: new dset: trying to start receiving data"%(self.name)
                # This may not work
                while bytes_recvd < length:
                    temp = self.try_recv()
                    arch_hash.update(temp)
                    bytes_recvd += len(temp)
                    dset_arch.write(temp)
                    #@arr.append(temp)
                    #bytes_recvd += len(arr[-1])
                if self.v: print "Thread %s: new dset: recv'd %i bytes"%(self.name, bytes_recvd)
                data = ''.join(arr)
            except ssl.socket_error:
                if self.v: print "Thread %s: new dset: timed out"%(self.name)
                self.req_fail('the connection timed out while transferring the dataset.')
                raise CThreadException()
            except IOError:
                if self.v: print "Thread %s: new dset: failed while writing archive"%(self.name)
                self.req_fail('there was an error while writing archive')
                raise CThreadException()
            except CThreadException as e:
                if self.v: print "Thread %s: new dset: %s"%(self.name, str(e))
                raise
    
                    
            if self.v: print "Thread %s: new dset: checking data integrity "%(self.name)
            svr_md5 = arch_hash.hexdigest()
            if svr_md5 != md5:
                if self.v: print "Thread %s: new dset: data integrity check failed "%(self.name)
                self.req_fail('the data received was different from the data sent due to a transmission error',)
                raise CThreadException()
                
            if self.v: print "Thread %s: new dset: writing archive "%(self.name)
            dset_arch.write(data)
            dset_arch.seek(0)
            
            
            # Extract archive, using only the base dset for each file, for security
            if self.v: print "Thread %s: new dset: Trying to extract archive "%(self.name)
            try:
                dset_arch.close()
                dset_arch = open(dset_arch.name, "rb")
                tar = tarfile.open(fileobj=dset_arch)
                if self.v: print "Thread %s: new dset: writing archive files "%(self.name)
                for fi in tar:
                    out = open(
                               os.path.join(dset_dir,
                               os.path.basename(fi.name)), 
                               'wb')
                    out.write(fi.tobuf())
                    out.close()
                if self.v: print "Thread %s: new dset: wrote dataset %s"%(self.name, os.path.basename(fi.name))
                dset_arch.close()
                if self.v: print "Thread %s: new dset: removing archive"%(self.name)
                os.remove(dset_arch.name)
            except tarfile.TarError as e:
                if self.v: print "Thread %s: new dset: opening tar failed %s"%(self.name,str(e))
                self.req_fail('the data received was not a valid tar archive')
            except IOError as e:
                if self.v: print "Thread %s: new dset: failed while writing dataset %s"%(self.name,str(e))
                self.req_fail('there was an error while writing the dataset')
                
            if self.v: print "Thread %s: new dset: new dataset addition OK"%(self.name)
            self.req_ok()
        except Exception as e:
            if self.v: print "Thread %s: new dset: cleaning up directories "%(self.name)
            if os.path.exists(dset_dir):
                try:
                    shutil.rmtree(dset_dir)
                except OSError:
                    #TODO: Notify an administrator about this
                    pass
            if type(e) != CThreadException:
                if self.v: print "Thread %s: new dset: caught non-CThread Exception; passing it on"%(self.name)
                raise
            
    def share(self, req):
        method = 'share'
        if self.v: print "Thread %s: share request: trying to get dset metadata"%(self.name)
        try:
            recip = req['recipient']
            dset = self.leaf(req['dset'])
            write = int(req['write']) 
            share = int(req['share']) 
            
            assert (write == 0 or write == 1) and (share == 0 or share == 1)
        except KeyError as e:
            self.handle_key_error(e, method)
            return
        except AssertionError as e:
            if self.v: 
                print "Thread %s: share: invalid value"%(self.name),
                print  "for \"write\' or \"share\""
            self.req_fail("write and share must be 0 or 1")
            return
        """
        dset_path = os.path.join(
                                 #self.permissions["dset_dir"],
                                 self.permissions["user_dir"],
                                 self.leaf(dset)
                                 )
        """
        dset_path = self.dset_path(dset)
        if not os.path.exists(dset_path):
            if self.v: print "Thread %s: share: dataset %s does not exist"%(self.name, dset)
            self.req_fail("dataset %s does not exist"%dset)
        
        if not os.access(dset_path, os.R_OK):
            if self.v: print "Thread %s: share: don't have permissions to read %s"%(self.name, dset)
            self.req_fail("COVI does not have permissions to read %s. Contact your administrator"%dset)
            
        if recip == self.permissions['uid']:
            self.req_fail("you can't share a dataset with yourself")
            return
        
        try:    
            if self.v: print "Thread %s: share: trying to add share request to database"%(self.name)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            if conn.execute(
                "SELECT * FROM shared_files WHERE owner=? AND recipient=? AND dataset=?;",
                [self.permissions['uid'], recip, dset]).fetchall():
                if self.v: print "Thread %s: share: duplicate share request"%(self.name)
                self.req_fail("there is already a pending share request for that user and dataset")
                return
            
            conn.execute('INSERT INTO shared_files VALUES (?, ?, ?, ?, ?, ?)', 
                               [self.permissions['uid'],
                                recip, dset, write, share, 1])
            conn.commit()
            self.req_ok()
        
        except sqlite3.Error as e:
            if self.v: print "Thread %s: share: share failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            return
        
        
    def share_response(self, req):
        method = 'share respsonse'
        if self.v: print "Thread %s: share response: trying to get dset metadata"%(self.name)
        try:
            owner = req['owner']
            dset = self.leaf(req['dset'])
            response = req['response']
            
            assert (response == 0 or response == 1)
        except (KeyError, AssertionError):
            self.handle_key_error(e, method)
            return

        if response:
            stmt = "UPDATE shared_files SET request = 0 WHERE owner=? AND recipient=? AND dataset=?"
        else:
            stmt = "DELETE FROM shared_files WHERE owner=? AND recipient=? AND dataset=?"
        
            
        try:    
            if self.v: 
                print "Thread %s: share response: "%(self.name),
                print "trying to add share response to database"
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            conn.execute(
                stmt,
                [owner, self.permissions['uid'], dset])
            conn.commit()
            self.req_ok()
                
        except sqlite3.Error as e:
            if self.v: print "Thread %s: share response: failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error: %s"%(str(e)))
        return
        
            
        
    def matrix(self, req):
        method = 'matrix'
        if self.v: print "Thread %s: matrix: trying to get dset metadata"%(self.name)
        try:
            dset = self.leaf(req['dset'])
            mat = int(req['number'])
            owner = ''
            
            if req['type'] == "shared matrix":
                owner = req['owner']
                
        except (KeyError, ValueError) as e:
            self.handle_key_error(e, method)
            return
        
        """dset_path = os.path.join(
                                self.permissions["user_dir"],
                                dset
                                )"""
        # If dset is not shared, load data from the local path
        if not owner:
            dset_path = self.dset_path(dset)
        else:
            try:
                if self.check_shared(owner, dset):
                    dset_path = self.shared_dset_path(owner, dset)
                else:
                    if self.v: 
                        print "Thread %s: copy: dataset %s is not shared with user"%(self.name, dset),
                        print "or it does not exist"
                    
                    self.req_fail("dataset %s is not shared with you or does not exist"%(dset))
                    return
                    
                    
            except sqlite3.Error:
                # check_shared does the appropriate error reporting for us
                return 
                
        
        # TODO: Determine file format definitively
        try:
            mat_file = open(os.path.join(dset_path,'%i.covi'%(mat)))
            data = mat_file.read()
            mat_file.close()
            
            md5_hash = hashlib.md5(data).hexdigest()
            mat_len = os.stat(mat_file.name).st_size
            resp = { "covi-response": { "type":"matrix", "len":mat_len, "md5":md5_hash} }
            self.client_socket.send(json.dumps(resp))
            try:
                reply = self.try_recv(2048)
            except CThreadException as e:
                if self.v: print "Thread %s: matrix request: %s"%(self.name, str(e))
                return
            try:
                reply = json.loads(reply)
                if reply["covi-request"]["type"] != "resp ok":
                    raise CThreadException("")
            except:
                if self.v: 
                    print "Thread %s: matrix request: invalid data in response from client"%(self.name)
                self.req_fail("it was missing required fields")
                return
            self.client_socket.send(data)
            
            
        except IOError as e:
            if self.v: print "Thread %s could not open matrix: %s"%(self.name, str(e))
            self.req_fail("matrix %i could not be opened"%(mat))
            return
        except Exception as e:
            if self.v: 
                print "Thread %s: matrix: error opening/sending matrix: %s"%(self.name, str(e))
            self.req_fail("there was an error reading or sending matrix %i"%(mat))
            return
        
    def list(self, req):
        # TODO: Add a special case for administrators
        method = 'list'
        if self.v: print "Thread %s processing list request"%(self.name)
        user_dir = self.permissions['user_dir']
        if self.v: print "Thread %s: list: checking dir %s"%(self.name, user_dir)
        dset_list = [name for name in os.listdir(user_dir) 
                     if os.path.isdir(self.dset_path(name))]
        self.permissions["dset_list"] = dset_list
        shared = []
        requests = []
        # Get shared datasets and requests
        try:    
            if self.v: print "Thread %s: auth: trying to fetch auth info from database"%(self.name)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            cur = conn.cursor()
            res = cur.execute('SELECT * FROM shared_files WHERE recipient=?', 
                              [self.permissions['uid']]).fetchall()
            
            
            # List comprehensions are fast
            shared = [i for i in res if i[5] == 0]
            requests = [i for i in res if i[5] == 1]
            conn.close()
        
        except sqlite3.Error as e:
            if self.v: print "Thread %s: list: listing failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            return
        try:
            self.client_socket.send(
                json.dumps(
                    { "covi-response": 
                        { "type":"list", 
                         "list":dset_list,
                         "shared":shared,
                         "requests":requests,
                         } 
                    }
                )
            )
            if self.v: 
                print "Thread %s: list: sent list of length %i"%(self.name, len(dset_list))
        except ssl.socket_error as e:
            if self.v: 
                print "Thread %s: list: error while sending directory list: %e"%(
                    self.name, str(e))
            return
            
        
    def rename(self, req):
        '''
        Rename a dataset from the name specified by req's "old" field to that specified 
        by it's "new" field.
        '''
        method = 'rename'
        if self.v: print "Thread %s: rename: trying to unpack old/new dset names"%(self.name)
        try:
            old = self.leaf(req['old'])
            new = self.leaf(req['new'])
            old_path = os.path.join(self.permissions['user_dir'], old)
            new_path = os.path.join(self.permissions['user_dir'], new)
            
            if self.v: print "Thread %s: rename: trying to rename dir"%(self.name)
            # If the file doesn't exist, we fail here, without touching the database
            os.rename(old_path, new_path)
            
            if self.v: 
                print "Thread %s: %s: renaming dataset %s in DB"%(self.name, method, old)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            
            conn.execute(
                'UPDATE shared_files SET dataset=? WHERE owner=? AND dataset=?',
                 [new, self.permissions['uid'], old])
            self.req_ok()
            return
        
        except KeyError as e:
            self.handle_key_error(e, method)
        except (OSError, IOError) as e:
            # If the directory could not be renamed
            """
                if e[0] == 39:
                    if self.v: print "Thread %s: rename: dataset already exists"%(self.name)
                    self.req_fail("a dataset with that name already exists")
                else:
                    if self.v: print "Thread %s: rename: could not rename directory: %s"%(self.name, str(e))
                    self.req_fail("the dataset's directory could not be renamed")
                return
                """
            print "Calling handle_env_error"
            self.handle_env_error(e, method)
        except sqlite3.Error as e:
            if self.v: print "Thread %s: rename: rename failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            # If the DB part failed, undo the directory rename
            try:
                os.rename(new_path, old_path)
            except:
                #FIXME: This would be REALLY BAD. DB is in an INCONSISTENT STATE.
                sys.stderr.write("ERROR: Renamed a dataset on disk but can't rename it in the DB or revert!!!")
            
    def remove(self, req):
        '''
        Delete a dataset, specified by the dset field of req.
        If it is shared with any other users, also remove references to the dataset
        in the shared_files table.
        '''
        method = 'remove'
        try:
            dset = self.leaf(req['dset'])
            
            if req['type'] == "remove admin":
                if not self.permissions['admin']:
                    print "Thread %s: remove: error: user"%(self.name, dset),
                    print 'used remove admin, but is not admin'
                    self.req_fail("you are not an administrator")
                owner = req['owner']
                dset_path = self.dset_path(dset, owner)
            else:
                dset_path = self.dset_path(dset)
                
        except KeyError as e:
            self.handle_key_error(e, method)
            return
        
        if not os.access(dset_path, os.W_OK):
            print "Thread %s: remove: error: dataset %s does not exist"%(self.name, dset),
            print "or is not writable."
            self.req_fail('dataset %s does not exist or is not writable'%(dset))
            return
            
        try:    
            if self.v: 
                print "Thread %s: remove: trying to remove shares from the"%(self.name),
                print "database for %s"%(dset)
            conn = sqlite3.connect("COVI_svr.db", timeout=20)
            if not owner:
                owner = self.permissions['uid']
            conn.execute(
                'DELETE FROM shared_files WHERE owner=? AND dataset=?',
                 [owner, dset])
            conn.commit()
            
            shutil.rmtree(os.path.join(dset_path))
            self.req_ok()
            return
        
        except sqlite3.Error as e:
            if self.v: print "Thread %s: share: share failed, DB error: %s"%(self.name, str(e))
            self.req_fail("of a database error")
            return
                
        except (OSError, IOError) as e:
            """
            if self.v: print "Thread %s: remove: could not delete dataset: %s: %s"%(self.name, 
                                                                                    full_name(e), 
                                                                                    str(e))
            self.req_fail("dataset %s could not be removed: %s"%(dset, e.message))
            return
            """
            self.handle_env_error(e, method)
        
    def remove_shared(self, req):
        method = 'remove shared'
        try:
            dset = req['dset']
            owner = req['owner']
        except KeyError as e:
            self.handle_key_error(e, method)
            return
        
        try:
            conn = sqlite3.connect('COVI_svr.db', timeout=20)
            conn.execute('DELETE FROM shared_files WHERE owner=? AND recipient=?'+
                         'AND dataset=?',[owner, self.permissions['uid'], dset])
            self.req_ok()
        except sqlite3.Error as e:
            if self.v: print "Thread %s: %s: share failed, DB error: %s"%(self.name, method, str(e))
            self.req_fail("of a database error")
            return
        
        
    def copy(self, req):
        method = 'copy'
        '''
        Handle a copy request or a copy shared request.
        Copy a local or shared dataset, specified in the "source" field of the 
        request, to a new dataset specified by the "destination" field.
        If the dataset is shared, it is copied from datadir/owner/source  
        '''
        try:
            source = req["source"]
            dest = req["destination"]
            shared = False
            
            if req["type"] == "copy shared":
                shared = True
                owner = req["owner"]
        except KeyError as e:
            """if self.v: print "Thread %s: copy: invalid data in copy request: %s: %s"%(self.name, 
                                                                          full_name(e), 
                                                                                 str(e))
            self.req_fail("it is missing required fields")
            """
            self.handle_key_error(e, method)
            return
        
        source_path = self.dset_path(source)
        if shared:
            try:
                # Make sure the dataset is shared with us before we try to copy it
                if self.check_shared(owner, source):
                    dest_path = os.path.join(self.config["data_dir"], owner, source)
                else:
                    if self.v: 
                        print "Thread %s: copy: dataset %s is not shared with user"%(self.name, source),
                        print "or it does not exist"
                    
                    self.req_fail("dataset %s is not shared with you or does not exist"%(source))
                    return
            except sqlite3.Error:
                # This was alredy handled
                return
            
        try:
            dest_path = self.dset_path(dest)
            shutil.copytree(source_path, dest_path)
            self.req_ok()
        except OSError as e:
            if self.v: 
                print "Thread %s: copy: could not copy dataset: %s"%(self.name, str(e))
                print "Source dir: %s"%(source_path)
                print "Dest dir: %s"%(dest_path)
            self.handle_env_error(e, method)
    
                    
    def keepalive(self, req):
        pass
        
        
        
    def close(self, req):
        self.client_socket.close()
        self.cont = False
        self.permissions = {}
        if self.v: print "Thread %s: close: connection closed"%(self.name)

            
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
