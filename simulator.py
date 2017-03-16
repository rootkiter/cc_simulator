#!/bin/python
###############################################
# File Name : simulator.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 3/16 20:54:32 2017
###############################################
import sys,os

class PackBase:
    def __init__(self):
        pass

    def buildcmd(self,cmdname,args):
        if(self._reg_member):
            return str(self._reg_member)
        return ""

import SocketServer
from SocketServer import ThreadingTCPServer, StreamRequestHandler
import threading

class MyTCPSocketHandler(StreamRequestHandler):
    def handle(self):
        try:
            print 'new client',self.client_address
            while True:
                ##################################### code here 
                ##################################### code here 
                data = self.request.recv(1)
                if not data:
                    break
                print data
                self.request.send(data) 
                
        except Exception,e:
            print str(e)

class MainControl:
    def __init__(self,model_name):
        self.simulator = None
        self.model_name=model_name
        self.re_load()
        self.args = {}

    def re_load(self):
        try:
            simulator = __import__(self.model_name)
            self.simulator=simulator.model()
            print self.simulator
        except Exception,e:
            print str(e)

    def send_cmd_packet(self,cmdname):
        cmd_pack=self.simulator.buildcmd(cmdname,self.args)
        print cmd_pack
        return True

    def startServer(self,port):
        addr = ('0.0.0.0',port)
        server = SocketServer.ThreadingTCPServer(addr,MyTCPSocketHandler) 
        startThread = threading.Thread(target=server.serve_forever)
        startThread.start()
        return True

def MainConsole(model_path,port):
    model_name = model_path.replace('.py','').strip()
    main_ctrl = MainControl(model_name)
    WhileFlag = main_ctrl.startServer(port)
    while(WhileFlag):
        try:
            sys.stdin.flush()
            sys.stdout.flush()
            cmdstr = str(raw_input(" cmd> "))
            cmdargs = cmdstr.split()
            if(len(cmdargs) ==0):
                continue
            elif(cmdargs[0] == 'exit'):
                return True
            else:
                flag =  main_ctrl.send_cmd_packet("stateCheck")
        except Exception,e:
            print str(e)

    return WhileFlag

def Eprint(logstr):
    print "[ERROR] ",logstr

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
