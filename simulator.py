#!/bin/python
###############################################
# File Name : simulator.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 3/16 20:54:32 2017
###############################################
import sys,os
from socket import *
import threading

def ConsolePrint(logstr,flag=False):
    print "\n",str(logstr),
    if( not flag):
        print "\n cmd> ",
    sys.stdout.flush()

def ErrorPrint(string):
    logstr = ""
    for item in string.split('\n'):
        logstr += "[ERROR] %s\n" % str(item)
    ConsolePrint(logstr)

def itembuild(mtype,value):
    result = ""
    if(mtype == 'str'):
        result += value
    elif(mtype in ['u32','-u32','u16','-u16']):
        buf = ("%08x" % (eval(str(value)))).upper()
        buflist=[ buf[2*x]+buf[2*x+1] for x in range(0,(len(buf)/2)) ]
        if(mtype == 'u32'):
            buflist  = buflist[::-1]
        elif(mtype == '-u32'):
            buflist  = buflist
        elif(mtype == 'u16'):
            buflist = buflist[2::]
            buflist = buflist[::-1]
        elif(mtype == '-u16'):
            buflist = buflist[2::]
        else:
            ErrorPrint("Just support [u32,-u32,u16,-u16] now...")
        for i in buflist:
            result += chr(int(i,16))
    else:
        ErrorPrint("Not Suppport this type:"+mtype)
    return result

class packBuilder:
    def __init__(self,size):
        self.size = size
        self.items = []

    def additem(self,offset,mtype,name,default):
        self.items.append([offset,mtype,name,default])
        self.items = sorted(self.items,key=lambda s: s[0])

    def getpacketstr(self):
        result=""
        current_offset=0
        if(len(self.items)==0):
            return result
        for k in range(0,len(self.items)):
            item = self.items[k]
            result += "\x00"*(item[0]-current_offset)
            result += itembuild(item[1],item[3])
            current_offset = len(result)
        result += '\x00'*(self.size - current_offset)

        return result

    def __str__(self):
        res = ""
        for i in self.items:
            res += str(i)
        return res

class hexmap:
    def __init__(self,string):
        self.string=string

    def __str__(self):
        (offset,hexdata,charbuf)=(0,"","")
        result=""
        for char in self.string:
            if ord(char)>=33 and ord(char)<=126:
                charbuf+=char
            elif ord(char)==0:
                charbuf+='.'
            else:
                charbuf+="\xff"

            hexdata+="%02x" % (ord(char))
            offset+=1
            i=(offset)%16
            if i==0:
                buf="0x%04x\t%-48s\t%-16s" % ((offset-1)/16*16,hexdata,charbuf)
                result += buf+"\n"
                hexdata=""
                charbuf=""
            elif (i%8==0):
                hexdata+="  "
            else:
                hexdata+=" "
        buf="0x%04x\t%-48s\t%-16s" % ((offset-1)/16*16,hexdata,charbuf)
        result += buf+"\n"
        result += "-----> packet size :hex(0x%x),ord(%d) <-------" % (len(self.string),len(self.string))
        return result

class PackBase:
    def __init__(self):
        pass

    def envcheck(self,membername,pflag=False):
        if(hasattr(self,membername)):
            return True
        if(not pflag):
            ErrorPrint("Didn't define "+membername+" in the config model")
        return False

    def checkcase(self,cmdname,pflag=False):
        if(self.envcheck("_testcase")):
            if( cmdname not in self._testcase):
                if(not pflag):
                    ErrorPrint("Not Found _testcase[\""+cmdname+"\"]")
                return False
            if( "fieldname" not in self._testcase[cmdname]):
                if(not pflag):
                    ErrorPrint("Not Found _testcase[\""+cmdname+"\"][\"fieldname\"]")
                return False
            if( "valuefix" not  in self._testcase[cmdname]):
                if(not pflag):
                    ErrorPrint("Not Found _testcase[\""+cmdname+"\"][\"valuefix\"]")
                return False
        return True

    def buildcmd(self,cmdname,args):
        if(self.envcheck("_cmd_members") 
            and self.envcheck("_cmdlen") 
            and self.envcheck("_testcase") 
            and self.checkcase(cmdname)):
            packbuild = packBuilder(eval(str(self._cmdlen)))
            for item in self._testcase[cmdname]['fieldname']:
                value = self._cmd_members[item][2]
                if(item in self._testcase[cmdname]['valuefix']):
                    value = self._testcase[cmdname]['valuefix'][item]
                if(item in args):
                    value = args[item]
                packbuild.additem(
                    self._cmd_members[item][1],
                    self._cmd_members[item][0],
                    item,
                    value
                )
            return packbuild.getpacketstr()
        return str(self._cmd_members)

    def isPingPong(self,data):
        if(self.envcheck("_registersize",True)
            and self.envcheck("_pingcheck",True)
            and self.envcheck("_reg_member",True)
        ):
            for item in self._pingcheck:
                if(item in self._reg_member):
                    matchstr = itembuild(self._reg_member[item][0],self._pingcheck[item])
                    if(not data[self._reg_member[item][1]::].startswith(matchstr)):
                        return False
        return True

    def on_recv(self,socket,data):
        print "recv -> " ,str(data)
        if(not self.isPingPong(data)):
            ConsolePrint( str(data))
        else:
            print "recv a pingpong"

class MyThread(threading.Thread):
    def __init__(self,function):
        threading.Thread.__init__(self)
        self.runflag = False
        self.function = function
        self.args = {}

    def update(self,args):
        self.args = args

    def run(self):
        if(self.function == None):
            return 
        self.runflag = True
        while(self.runflag):
            import time
            time.sleep(0.1)
            if(self.args != None and 
                len(self.args)>=0):
                args = self.args
                self.args = {}
                self.function(args)

    def stop(self):
        print "thread stop"
        self.runflag = False
        print "thread stop ok"

class MySocketServer:
    def __init__(self,port,handle,maxlisten=10000):
        self.port=port
        self.maxlisten = maxlisten
        self.socket = None
        self.handle = handle
        self.ServerThread = None
        self.maxrecvlen   = 1024
        self.clients = []

    def startServer(self):
        self.socket = socket(AF_INET,SOCK_STREAM)
        self.socket.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
        self.socket.bind(('0.0.0.0',self.port))
        self.socket.listen(self.maxlisten)
        def cbf_for_server(args):
            if(len(args)!= 1 or 
                'self' not in args
            ):
                return False
            socket       = args['self'].socket
            clients      = args['self'].clients
            try:
                while True:
                    import select
                    rs,ws,es = select.select(clients+[socket],[],[])
                    for r in rs:
                        disconnect = False
                        data = ""
                        newconnect = False
                        if r is socket:
                            connect,address = self.socket.accept()
                            print 'new client here %s,%s' % (str(connect),str(address))
                            clients.append(connect)
                            newconnect  = True
                        else:
                            try:
                                data = r.recv(args['self'].maxrecvlen)
                                if(len(data)==0):
                                    disconnect = True
                            except Exception,e:
                                disconnect=True
                        if disconnect and not newconnect:
                            clients.remove(r)
                            r.close()
                        elif (not newconnect):
                            print "new msg here"
                            args['self'].on_recv(r,data)
                        else:
                            pass
            except Exception,e:
                print str(e)
                socket.close()
                return False
            
        self.ServerThread = MyThread(cbf_for_server)
        args = {
            'self':self
        }
        self.ServerThread.update(args)
        self.ServerThread.start()

    def on_recv(self,client,data):
        self.handle.on_recv(client,data)
        
    def sendall(self,data):
        besendnum = 0
        for client in self.clients:
            try:
                nsend = client.send(data)
                besendnum +=1
            except Exception,e:
                self.clients.remove(client)
        return besendnum

    def stopServer(self):
        if(self.ServerThread):
            self.ServerThread.stop()
        if(self.socket):
            print "try close socekt"
            self.socket.close()

class MainControl:
    def __init__(self,model_name):
        self.simulator = None
        self.model_name=model_name
        self.server = None
        self.config = None
        self.re_load()
        self.args = {}

    def re_load(self):
        try:
            print "reloading now !!!"
            if(self.config == None):
                self.config = __import__(self.model_name)
                self.simulator=self.config.model()
            else:
                self.config=reload(self.config)
                self.simulator=self.config.model()
        except Exception,e:
            print str(e)

    def send_cmd_packet(self,cmdname):
        cmd_pack=self.simulator.buildcmd(cmdname,self.args)
        ConsolePrint(hexmap(cmd_pack),True)
        self.server.sendall(cmd_pack)
        return True

    def startServer(self,port,host='0.0.0.0'):
        try:
            addr = (host,port)
            self.server = MySocketServer(port,self.simulator)
            self.server.startServer()
            return True
        except Exception,e:
            print str(e)
            return False

    def stopServer(self):
        self.server.stopServer()
        return True

def MainConsole(model_path,port):
    model_name = model_path.replace('.py','').strip()
    main_ctrl = MainControl(model_name)
    WhileFlag = main_ctrl.startServer(port)
    while(WhileFlag):
        try:
            sys.stdin.flush()
            sys.stdout.flush()
            cmdstr = str(raw_input("\n cmd> "))
            cmdargs = cmdstr.split()
            if(len(cmdargs) ==0):
                continue
            elif(cmdargs[0] == 'exit'):
                main_ctrl.stopServer()
                return True
            elif(cmdargs[0] == 'reload'):
                main_ctrl.re_load()
                continue
            else:
                flag =  main_ctrl.send_cmd_packet("stateCheck")
        except Exception,e:
            print str(e)

    return WhileFlag

def Eprint(logstr):
    print "[ERROR] ",logstr

def TestPrint(sock,data):
    print "recv --> " , str(data)
    print dir(sock)
    sock.send("recv\n")

if __name__=='__main__00':
    myserver = MySocketServer(8888,TestPrint)
    myserver.startServer()
    i=0
    while (i<10):
        import time
        time.sleep(1)
        logstr = "[%d] clients num = %d" % (i,len(myserver.clients))
        print logstr
        myserver.sendall(logstr)
        i=i+1
    print "stop"
    myserver.stopServer()
    print "stop ok"

if __name__=='__main__2':
    thread = MyThread()
    thread.start()
    import time
    time.sleep(5)
    thread.stop()

if __name__=='__main__':
    print "Hello World ! "
    print sys.argv
    if(len(sys.argv) != 3):
        print sys.argv[0],'[model_path] [port]'
        exit()
    elif(not os.path.exists(sys.argv[1])):
        Eprint("Please check the model_path,I cannot find it")
        exit()
    else:
        flag = MainConsole(sys.argv[1],int(sys.argv[2]))
        if(flag == False):
            Eprint("Server Start Error")
            exit()

