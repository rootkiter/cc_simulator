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

class tablemap:
    def __init__(self):
        self.titlelist={}
        self.item = {}
        self.itemnamelen=0
        self.itemlist = []

    def additem(self,title,itemname,itemvalue):
        if(title not in self.titlelist):
            self.titlelist[title]=len(title)
        if(itemname not in self.item):
            self.item[itemname] = {}
            self.itemlist.append(itemname)
        self.item[itemname][title]=str(itemvalue)
        if(self.titlelist[title] < len(str(itemvalue))):
            self.titlelist[title] = len(str(itemvalue))
        if(len(itemname) > self.itemnamelen):
            self.itemnamelen = len(itemname)
        return True

    def getItemString(self,List,itemname,itemList=None):
        result = "| "
        if(itemList == None):
            formatString = "%%-%ds |" % self.itemnamelen
            result += formatString % itemname
            for citem in List:
                if(citem.startswith('-')):
                    item = citem[1::]
                    formatString = " %%-%ds |" % self.titlelist[item]
                else:
                    item = citem
                    formatString = " %%%ds |" % self.titlelist[item]
                itembuf = (((self.titlelist[item] - len(item))/2)*' ')+item
                result += formatString % (itembuf)
        else:
            formatString = "%%-%ds |" % self.itemnamelen
            result += formatString % itemname
            for citem in List:
                if(citem.startswith('-')):
                    item = citem[1::]
                    formatString = " %%-%ds |" % self.titlelist[item]
                else:
                    item = citem
                    formatString = " %%%ds |" % self.titlelist[item]
                try:
                    result += formatString % str(itemList[item])
                except Exception, e:
                    result += formatString % ""
        return result

    def printMap(self,titleList=None):
        result = ""
        formatString = "| "
        lineK        = "+-"
        List = []
        if(titleList == None):
            for item in self.titlelist :
                List .append(item)
        else:
            List = titleList
        formatString += "%%%ds |" % self.itemnamelen
        lineK += self.itemnamelen*'-' + "-+"
        for citem in List:
            if(citem.startswith('-')):
                item=citem[1::]
                formatString += " %%-%ds |" % self.titlelist[item]
            else:
                item=citem
                formatString += " %%%ds |" % self.titlelist[item]
            lineK += "-"+ self.titlelist[item]*'-' + "-+"

        result += lineK +"\n"
        result += self.getItemString(List,"") + "\n"

        result += lineK +"\n"
        for item in self.itemlist:
            try:
                result += self.getItemString(List,item,self.item[item]) +"\n"
            except Exception, e:
                str(e)
        result += lineK +"\n"
        return result

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
                charbuf+="*"

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

def addlinehead(data,linehead):
    result = ""
    for line in data.split("\n"):
        result += linehead+line+"\n"
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

    def has_cmd_name(self,cmdname):
        if(self.envcheck("_cmd_members")
            and self.envcheck("_cmdlen")
            and self.envcheck("_testcase")
            and self.checkcase(cmdname)):
                return True
        return False

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
        if(not self.isPingPong(data)):
            ConsolePrint( str(hexmap(data)))

    def showfields(self,cmdname=None):
        result = "Fields Tables:\n"
        if(self.envcheck("_cmd_members")
            and self.envcheck("_testcase")
        ):
            tbmap = tablemap()
            fieldslist = []
            if(cmdname != None and cmdname in self._testcase):
                fieldslist = self._testcase[cmdname]['fieldname']
            else:
                fieldslist = self._cmd_members.keys()

            showlist = []
            for item in fieldslist:
                value = self._cmd_members[item]
                showlist .append([value[1],item,value[2]])
            showlist = sorted(showlist,key = lambda s:s[0])
            for item in showlist:
                tbmap.additem('hex'  ,item[1],"+0x%x" % eval(str(item[0])))
                tbmap.additem('ord'  ,item[1],  "+%d" % eval(str(item[0])))
                tbmap.additem('value',item[1],  "%s" % str(item[2]))
            result += addlinehead(tbmap.printMap(['-hex','-ord','-value']),"    ")
        return result
                    
    def showfixvalue(self,cmdname):
        result = ""
        if(self.envcheck("_cmd_members")
            and self.envcheck("_testcase")
            and cmdname in self._testcase
            and 'valuefix' in (self._testcase[cmdname])
        ):
            result += "FixValue Table:\n"
            tbmap = tablemap()
            for item in self._testcase[cmdname]['valuefix']:
                tbmap.additem('fix_value',item,str(self._testcase[cmdname]['valuefix'][item]))
            result += addlinehead(tbmap.printMap(['-fix_value']),"    ")
        return result

    def showtestcase(self,cmdname = None):
        result = ""
        if(self.envcheck("_cmd_members")
            and self.envcheck("_testcase")
        ):
            result += "TestCase :\n"
            tbmap = tablemap()
            if(cmdname == None):
                for item in self._testcase:
                    tbmap.additem("fieldslist",item,str(self._testcase[item]['fieldname']))
            else:
                tbmap.additem("fieldslist",cmdname,str(self._testcase[cmdname]['fieldname']))
            result += addlinehead(tbmap.printMap(['-fieldslist']),"    ")
        return result

    def help_page(self,cmdname=None):
        result = ""
        result += self.showfields(cmdname)
        return result
    
    def show_page(self,cmdname=None):
        result = ""
        result += self.showfields(cmdname)
        if(cmdname != None):
            result += self.showfixvalue(cmdname)
        return result

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
        self.runflag = False

class MySocketServer:
    def __init__(self,port,handle,maxlisten=10000):
        self.port=port
        self.maxlisten = maxlisten
        self.socket = None
        self.handle = handle
        self.ServerThread = None
        self.maxrecvlen   = 10240
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
            self.socket.close()

class MainControl:
    def __init__(self,model_name):
        self.simulator = None
        self.model_name=model_name
        self.server = None
        self.config = None
        self.re_load()
        self.args = {}

    def has_cmd(self,cmdname):
        return self.simulator.has_cmd_name(cmdname)

    def setArgs(self,payload,value):
        self.args[payload]=value

    def removeArgs(self,payload):
        if(payload in self.args):
            self.args.pop(payload)

    def help_page(self,cmdname=None):
        result = "Commands Table:\n"
        tbmap = tablemap()
        tbmap.additem("infomation","reload","Reload the config file.")
        tbmap.additem("infomation","set","Set Payload Value.")
        tbmap.additem("infomation","unset","Cancel Payload Value.")
        tbmap.additem("infomation","show","Show Payload Values.")
        tbmap.additem("infomation","help","This Help Page.")
        result += addlinehead( tbmap.printMap(['-infomation']),"    ")
        result += self.simulator.showtestcase(cmdname)
        return result

    def show_page(self,cmdname=None):
        result = self.simulator.show_page(cmdname)
        if(len(self.args)>0):
            tbmap = tablemap()
            result += "Set Value Table:\n"
            for item in self.args:
                tbmap.additem("Set Value",item,self.args[item])
            result += addlinehead( tbmap.printMap(["-Set Value"]),"    ")
        return result

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
            elif(cmdargs[0] == 'help'):
                if(len(cmdargs)>1):
                    ConsolePrint(main_ctrl.help_page(cmdargs[1]))
                else:
                    ConsolePrint(main_ctrl.help_page())
                continue
            elif(cmdargs[0] == 'show'):
                if(len(cmdargs)>1):
                    ConsolePrint(main_ctrl.show_page(cmdargs[1]))
                else:
                    ConsolePrint(main_ctrl.show_page())
                continue
            elif(cmdargs[0] == 'set'):
                if(len(cmdargs)!=3):
                    Eprint("RE Check the command")
                else:
                    main_ctrl.setArgs(cmdargs[1],cmdargs[2])
            elif(cmdargs[0] == 'unset'):
                if(len(cmdargs)!=2):
                    Eprint("RE Check the command")
                else:
                    main_ctrl.removeArgs(cmdargs[1])
            else:
                if(main_ctrl.has_cmd(cmdargs[0])):
                    flag =  main_ctrl.send_cmd_packet(cmdargs[0])
                else:
                    Eprint("RE Check the command")
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

