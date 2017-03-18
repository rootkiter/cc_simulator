#!/bin/python
###############################################
# File Name : bot_9527.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 3/16 20:57:40 2017
###############################################

from simulator import PackBase

class model(PackBase):
    # register config 
    _registersize=10
    _reg_member={
        "cmdgroup"    :[  "u32" ,  0x00    , 5              ],
    }
    # if has ping_pong packet
    _pingcheck={
        "cmdgroup":5,
    }

    # cmd packet config
    _cmdlen=20
    _cmd_members={
        #  field-name  ,  type  ,  offset  , default_value 
        "cmdgroup"    :[  "u32" ,  0x00    , 5              ],
        "targetip"    :[  "str" ,  0x04    , "192.168.119.1"],
        "port"        :[  "-u16" , 0x00    , 8888           ],
    }

    # one case for one cmd packet
    _testcase={
        "stateCheck":{
                "fieldname":["cmdgroup"],
                "valuefix" :{"cmdgroup":"0x31"},
                # if has result
                "acksize"  :20,
        },
    }

    _samples={
        '2b770a153d3cbd14bdc85e921e5bad75'
    }

    def buildcmd1(self,cmdname,args):
        if(self._reg_member):
            return "111"+str(self._reg_member)
        return ""
