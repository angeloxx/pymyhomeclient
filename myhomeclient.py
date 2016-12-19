import asyncore, socket, hmac, hashlib, random, string

class MHClient():
    def __init__(self,ipaddress):
        self.ipaddress = ipaddress
        self.command = MHConnection(self.ipaddress,20000,"COMMAND","12345")
        self.monitor = MHConnection(self.ipaddress,20000,"MONITOR","12345")        

    def sendCommand(self,command):
        self.command.write(command)


class MHConnection(asyncore.dispatcher):
    def __init2__(self):
        pass
    def __init__(self, host, port, type, password):
        self.host = host
        self.port = port
        self.type = type
        self.password = password
        self.state = 0
        self.buffer = ""
        self.commandqueue = []
        self.expectedAnswer = ""

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect( (self.host, self.port))

    def handle_connect(self):
        print "State[%s]: Connected" % (self.type)

    def handle_close(self):
        self.close()
        self.connect( (self.host, self.port))

    def handle_read(self):
        read = self.recv(8192)
        print "State[%s]: %d, read: <%s>" % (self.type, self.state, read)
        if self.state == 0 and read == "*#*1##":
            self.state = 1
            if self.type == "COMMAND":
                self.buffer = "*99*0##"
            elif self.type == "MONITOR":
                self.buffer = "*99*1##"
        elif self.state == 1 and read == "*#*1##":
            # Ready for command/monitor, free access
            self.state = 100
        elif self.state == 1 and read == "*98*2##":
            # HMAC Challenge password
            self.state = 10
            self.buffer = "*#*1##"
        elif self.state == 10:
            # RA offer received
            self.state = 11
            ra = read[2:-2]
            self.buffer = self.calcHMAC(ra,self.password)
        elif self.state == 11 and read == self.expectedAnswer:
            self.state = 100
            self.buffer = '*#*1##' + ''.join(self.commandqueue)
        
    def calcHMAC(self,ra,password):
        if len(ra) == 80:
            # SHA1 Algo
            rb = hashlib.sha1(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))).hexdigest()
            message = hashlib.sha1(self.digitToHex(ra)+rb+"736F70653E"+"636F70653E"+hashlib.sha1(password).hexdigest()).hexdigest()
            self.expectedAnswer = "*#%s##" % self.hexToDigit(hashlib.sha1(self.digitToHex(ra)+rb+hashlib.sha1(password).hexdigest()).hexdigest())
            return "*#%s*%s##" % (self.hexToDigit(rb),self.hexToDigit(message))
        elif len(ra) == 128:
            # SHA256 Algo
            rb = hashlib.sha256(''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))).hexdigest()
            message = hashlib.sha256(self.digitToHex(ra)+rb+"736F70653E"+"636F70653E"+hashlib.sha256(password).hexdigest()).hexdigest()
            self.expectedAnswer = "*#%s##" % self.hexToDigit(hashlib.sha256(self.digitToHex(ra)+rb+hashlib.sha256(password).hexdigest()).hexdigest())
            return "*#%s*%s##" % (self.hexToDigit(rb),self.hexToDigit(message))

    def digitToHex(self,_in):
        out = ""
        i = 0
        while (i < len(_in)):
            out = out + "%x%x" % ((int(_in[i])*10+int(_in[i+1])),(int(_in[i+2])*10+int(_in[i+3])))
            i = i + 4
        return out

    def hexToDigit(self,_in):
        out = ""
        i = 0
        while (i < len(_in)):
            out = out + ("%d%d" % (int(_in[i],16)/10, int(_in[i],16) % 10))
            i = i + 1
        return out

    def writable(self):
        return (len(self.buffer) > 0)

    def handle_write(self):
        sent = self.send(self.buffer)
        print "State[%s]: %d, sent: <%s>" % (self.type, self.state, self.buffer[:sent])
        self.buffer = self.buffer[sent:]

    def write(self, buffer):
        if (self.state < 100):
            self.commandqueue.append(buffer)
        else:
            self.buffer = self.buffer + buffer
