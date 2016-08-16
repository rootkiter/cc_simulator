#!/bin/python
###############################################
# File Name : bot9527.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : Wed 20 Jul 2016 12:25:57 AM PDT
###############################################


packetsize=516
regsize=372
packet={
    #  field-name  ,  type  ,  offset  , default_value 
    "cmdgroup"    :[  "u32" ,  0x00    , 5              ],
    "targetip"    :[  "str" ,  0x04    , "192.168.119.1"],
    "port"        :[  "u16" ,  196     , 8888           ],
    "ddosway"     :[  "u32" ,  200     , 1              ],
    "threads"     :[  "u32" ,  204     , 5              ],
    "times"       :[  "u32" ,  208     , 3              ],
    "minpayload"  :[  "u32" ,  212     , 10             ],
    "maxpayload"  :[  "u32" ,  216     , 20             ],
    "configarg1"  :[  "u32" ,  220     , 1              ],
    "configarg2"  :[  "u32" ,  224     , 10             ],
    "configarg3"  :[  "u32" ,  228     , 20             ]
}

testcase={
    "stateCheck":{
            "fieldname":["cmdgroup"],
            "valuefix" :{"cmdgroup":"0x31"},
            "acksize"  :377
    },
    "stop":{
            "fieldname":["cmdgroup"],
            "valuefix" :{"cmdgroup":"0x02"}
    },
    "setconfig":{
            "fieldname":["cmdgroup","configarg1","configarg2","configarg3"],
            "valuefix" :{"cmdgroup":"0x03"}
    },
    "checkconfig":{
            "fieldname":["cmdgroup"],
            "valuefix" :{"cmdgroup":"0x04"},
            "acksize"  :236
    },
    "attack":{
            "fieldname":["cmdgroup","targetip","port","ddosway",
                    "threads","times","minpayload","maxpayload"],
            "valuefix" :{"cmdgroup":"0x01","ddosway":"0x05"}
    }
}

cmdhelp={
    'tcp_flood':4,
    'udp_flood':2,
    'dns_rand_flood':3,
    'cc_flood':5,
    'syn_flood':1
}

sampleList=[
    '2b770a153d3cbd14bdc85e921e5bad75'
]