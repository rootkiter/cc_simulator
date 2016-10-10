#!/bin/python
###############################################
# File Name : simulator.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : Wed 20 Jul 2016 12:18:02 AM PDT
###############################################

from SocketServer import ThreadingTCPServer, StreamRequestHandler
import traceback,time,os,sys


global_config_name=""
global_config_file=None
global_payload={}

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

def ErrorPrint(msg):
    sys.stdout.flush()
    sys.stdin.flush()
    print "[ Error ] %s" % (msg)

def EGPrint(msg):
    sys.stdout.flush()
    sys.stdin.flush()
    print "[  EG   ] %s" % (msg)

def typecheck(value,typestr):
    if(typestr == "int"):
        return type(1)==type(value)
    elif(typestr == "list"):
        return type([1])==type(value)
    elif(typestr == "dict"):
        return type({"1":1})==type(value)
    elif(typestr == "str"):
        return type("1")==type(value)
    else:
        ErrorPrint("Unknown (int,list,dict) ,typestr=" + typestr)
        return False

def configcheck(config):
    if not "testcase" in dir(config):
        EGPrint("need \'testcase\' value")
        EGPrint("eg: ")
        EGPrint("    testcase={")
        EGPrint("        \"ddos\":{")
        EGPrint("            \"fieldname\":[\"cmdgroup\"],")
        EGPrint("            \"valuefix\" :{\"cmdgroup\":\"0x03\"},")
        EGPrint("            \"ackflag\":1")
        EGPrint("    }")
        return False
    if not "packetsize" in dir(config):
        ErrorPrint("no packetsize field")
        ErrorPrint("eg: ")
        ErrorPrint("    packetsize=516")
        return False
    if not "packet" in dir(config):
        ErrorPrint("no testcase field")
        return False


    if not typecheck(config.packetsize,"int"):
        ErrorPrint(" type(packetsize) need be int")
        return False
    if not typecheck(config.regsize,"int"):
        ErrorPrint(" type(regsize) need be int")
        return False
    if not typecheck(config.packet,"dict"):
        ErrorPrint(" type(packet) need be dict")
        return False
    if not typecheck(config.testcase,"dict"):
        ErrorPrint(" type(testcase) need be dict")
        return False
    
    for item in config.packet:
        descript=config.packet[item]
        if len(descript) != 3:
            ErrorPrint(" len(config.packet[item]) != 3 --> "+
                str(item)+":"+str(descript))
            return False

        if not (typecheck(descript[0],"str") and 
                typecheck(descript[1],"int")):
            ErrorPrint(" typeError (str,int,int,xxx) --> "+str(descript))
            return False

    for casename in config.testcase:
        case=config.testcase[casename]
        if not typecheck(case,"dict"):
            ErrorPrint(" typeError type(config.testcase.item) --> "+str(case))
            return False
        if not "fieldname" in case:
            ErrorPrint(" \"fieldname\" item lost --> "+str(case))
            return False
        if not typecheck(case["fieldname"],"list"):
            ErrorPrint(" type(config.testcase.item[fieldname] != list --> "+str(case))
            return False

        for fieldname in case["fieldname"]:
            if not fieldname in config.packet:
                errstr  = "field not match --> ("+fieldname +") in "
                errstr += "config.testcase[\""+casename+"\"][\"fieldname\"] "
                errstr += " not found in config.packet "
                ErrorPrint(errstr)
                return False


        if not "valuefix" in case:
            ErrorPrint(" \"valuefix\" item lost --> "+str(case))
            return False
        if not typecheck(case["valuefix"],"dict"):
            ErrorPrint(" type(config.testcase.item[valuefix] != list --> "+str(case))
            return False
    return True

def buildbuf(Type,value):
    res=""
    if(type(value)==type(1)):
        buf = ("%08x" % (value)).upper()
        buflist=[ buf[2*x]+buf[2*x+1] for x in range(0,(len(buf)/2)) ]
        if Type=="u32":
            buflist=buflist[::-1]
        elif Type=="-u32":
            buflist=buflist
        elif Type=="u16":
            buflist=buflist[2::]
            buflist=buflist[::-1]
        elif Type=="-u16":
            buflist=buflist[2::]
        for i in buflist:
            res += chr(int(i,16))
        
    elif(type(value)==type("1")):
        if Type=="str":
            res += value
        else:
            ErrorPrint("Not str ? --> "+ Type +":"+value)
    else:
        print "??????????"
    return  res

class packetBuilder:
    def __init__(self,size):
        self.size=size
        self.descript=[]

    def addDescript(self,offset,Type,name,default):
        self.descript.append([offset,Type,name,default])
        self.descript = sorted(self.descript,key=lambda s: s[0])

    def getpacketstr(self):
        result=""
        current_offset=0
        for item in self.descript:
            result += "\x00"*(item[0]-current_offset)
            result += buildbuf(item[1],item[3])
            current_offset=len(result)
        result+= "\x00"*(self.size-current_offset)
        return result
            
    def __str__(self):
        res = ""
        for i in self.descript:
            res += str(i)
        return res

def buildpacket(cmdstr,payloads,config):
    if not cmdstr in config.testcase:
        ErrorPrint(" No cmd description --> "+cmdstr)
        return "Error"
    packet=packetBuilder(config.packetsize)
    case=config.testcase[cmdstr]
    
    for field in case["fieldname"]:
        item = config.packet[field]
        if(payloads and field in payloads):
            packet.addDescript(item[1],item[0],field,payloads[field])
        else:
            packet.addDescript(item[1],item[0],field,item[2])

    return packet.getpacketstr()



def mload(config,args):
    global_config_file=reload(config)
    return global_config_file
    
def mset(config,args):
    if(len(args)!=3):
        mhelp(config,['help','set'])
        return False
    else:
        if(not args[1] in config.packet):
            ErrorPrint("no payload --> "+args[1])
            return False
        else:
            item=config.packet[args[1]]
            if(typecheck(item[2],"int")):
                global_payload[args[1]]=int(args[2])
            elif(typecheck(item[2],"str")):
                global_payload[args[1]]=str(args[2])
            else:
                ErrorPrint("Unknown the type --> "+args[1])
                return False
    return True

def muset(config,args):
    if(len(args)!=2):
        mhelp(config,['help','unset'])
        return False
    else:
        if(not args[1] in global_payload):
            ErrorPrint("no found unset item --> "+args[1])
            return False
        else:
            global_payload.pop(args[1])

def mshow(config,args):
    print "packetsize -> ",config.packetsize

    m_payloadlist=[]
    if(len(args)==2 and args[1] in config.testcase):
        m_showlist = config.testcase[args[1]]["fieldname"]
    else:
        m_showlist = config.packet

    print "+%60s+" % ('-'*60)
    print "| %-9s %-7s %-16s:  %s  " % ("hex","ord","payload","value")
    print "+%60s+" % ('-'*60)

    showlist=[]
    for item in m_showlist:
        value=config.packet[item]
        showlist.append([value[1],item,value[2]])

    showlist = sorted(showlist,key=lambda s: s[0])

    for item in showlist:
        if(typecheck(item[2],"str")):
            print "| +0x%-6x +%-6d %-16s:\"%s\"" % (item[0],item[0],item[1],item[2])
        elif(typecheck(item[2],"int")):
            print "| +0x%-6x +%-6d %-16s: %d"    % (item[0],item[0],item[1],item[2])
        else:
            ErrorPrint("Unknown payload Type -->",item)
    print "+%60s+" % ('-'*60)

    print "| set  payload :"
    for item in global_payload:
        print "|\t%-10s : " % (item) , global_payload[item]

    print "+%60s+" % ('-'*60)
    return
            
def mhelp(config,args):
    if(len(args)!=1):
        if(args[1] in cmdlist):
            print cmdlist[args[1]][2]
        elif(args[1] in config.testcase):
            mshow(config,['show',args[1]])
            print "| fixvalue:"
            case=config.testcase[args[1]]
            for i in case['valuefix']:
                print "| \t%-10s : %s" % (i,case['valuefix'][i])
            print "+%60s+" % ('-'*60)
                
    else:
        print "+%30s+" % ("-"*30)
        print "| inline commands:"
        for i in cmdlist:
            print "| %-10s : %s" % (i,cmdlist[i][1])
        print "+%30s+" % ("-"*30)
        print "\n payloads :\n"
        for i in config.packet:
            print "\t%s\n" % ("\""+i+"\"") ,

        print "\n\n testcase commands:\n"
        for i in config.testcase:
            print "\t%s\n" % ("\""+i+"\"") ,
        print "\n"


cmdlist={ 
    "help"  :[mhelp ,"Help Page"             ,"[help | help set ]"],
    "set"   :[mset  ,"Set The Payload Value" ,"[set targetip 127.0.0.1]"],
    "show"  :[mshow ,"Show The Payloads"     ,"[show | show attack ]"],
    "reload":[mload ,"Reload The configfile" ,"[reload]"],
    "unset" :[muset ,"Remove The Payload set","[unset targetip]"]
}

def myConsole():
    global_config_file=__import__(global_config_name)
    try:
        while True:
            try:
                sys.stdout.flush()
                sys.stdin.flush()
                x=str(raw_input(" cmd> "))
                inputlist=x.split(" ")
                inputbuf=[]
                for item in inputlist:
                    if(len(item)>0):
                        inputbuf.append(item)
                inputlist=inputbuf
                if (len(inputlist)>=1 and inputlist[0] in cmdlist):
                    if(cmdlist[inputlist[0]][0]):
                        cmdlist[inputlist[0]][0](global_config_file,inputlist)
                elif(len(inputlist)>=1 and inputlist[0]=="exit"):
                    break;
                    raise
                elif(len(inputlist)>=1 and inputlist[0] in global_config_file.testcase):
                    payloadbuf={}
                    case = global_config_file.testcase[inputlist[0]]

                    for i in case['valuefix']:
                        if i in global_config_file.packet:
                            if(typecheck(global_config_file.packet[i][2],"str")):
                                payloadbuf[i]=case['valuefix'][i]
                            elif(typecheck(global_config_file.packet[i][2],"int")):
                                mbuf=case['valuefix'][i]
                                if "0x" in mbuf:
                                    payloadbuf[i]=int(mbuf.replace('0x',''),16)
                                else:
                                    payloadbuf[i]=int(mbuf,10)

                    for i in global_payload:
                        payloadbuf[i]=global_payload[i]

                    packstr=buildpacket(inputlist[0],payloadbuf,global_config_file)
                    global_botclients.sendData(packstr)
                    if 'acksize' in global_config_file.testcase[inputlist[0]]:
                        size=global_config_file.testcase[inputlist[0]]['acksize']
                        if typecheck(size,"int"):
                            global_botclients.recvData(size)
                else:
                    ErrorPrint ("command error re-input.")
                    continue
            except:
                ErrorPrint("Error in myConsole while Loop")
    except:
        traceback.print_exc()
        ErrorPrint("Error in myConsole")
    exit(1)

class botclients:
    def __init__(self):
        self.clients=[]

    def addclient(self,instream,outstream,clientinfo):
        item={"in":instream,"out":outstream,"info":clientinfo}
        config=__import__(global_config_name)
        if(config.regsize and config.regsize>0):
            regdata=instream.read(config.regsize)
            print "reg packet"
            print str(hexmap(regdata))
        self.clients.append(item)

    def sendData(self,data):
        sys.stdout.flush()
        sys.stdin.flush()
        print "---------> data be send <---------------"
        print str(hexmap(data))
        i=0
        for item in self.clients:
            print "start send to -> ",item["info"].client_address
            try:
                item["out"].write(data)
            except:
                del self.clients[i]
                ErrorPrint("Error Send")
            i+=1

#            print dir(item["info"])
            
    def recvData(self,maxlen):
        for item in self.clients:
            data=item["out"].read(maxlen)
            print str(hexmap(data))
    
    def getclientNum(self):
        return len(self.clients)

global_botclients=botclients()

class MyStreamRequestHandler(StreamRequestHandler):
    def handle(self):
        try:
#           print dir(self)
#           print self.client_address
#           print self.connection
#           print self.disable_nagle_algorithm
#           print self.server
#           print dir(self.server)
#           self.server.server_close()
            print "new Client here"
            global_botclients.addclient(self.rfile,self.wfile,self)
            if(global_botclients.getclientNum()==1):
                myConsole()
            while True:
                time.sleep(10000)
        except:
            traceback.print_exc()
            ErrorPrint("Error in MyStreamRequestHandler")
            pass

def start_CC_simulator(configname,listenport):
    global global_config_file
    global global_config_name
    global global_payload

    global_config_name=configname
    print global_config_name
    config=__import__(configname)
    if (not configcheck(config)):
        ErrorPrint( "Syntax error in config file")
    else:
        addr=("",listenport)
        server=ThreadingTCPServer(addr,MyStreamRequestHandler)
        server.serve_forever()

#       packstr=buildpacket("attack",{"port":9999},config)
#       print str(hexmap(packstr))

if __name__=="__main__":
    if (len(sys.argv) != 3):
        print sys.argv[0],"[config_name] [listen_port]"
        print "eg: "
        print "    ",sys.argv[0],"bot9527 8888"
    else:
        configfile=sys.argv[1]+".py"
        if(not os.path.exists(configfile)):
            print "no found file",configfile
        else:
            global_config_name=sys.argv[1]
            start_CC_simulator(sys.argv[1],int(str(sys.argv[2])))
