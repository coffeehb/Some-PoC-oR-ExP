## commons-io 库中的 目录穿越问题-CVE-2021-29425

在2.7之前的Apache Commons IO中，调用方法时
FileNameUtils.normalize在处理输入的字符串时存在缺陷，normalize 方法作用是对传入的路径进行格式化操作，以符合当前系统文件格式要求。
在存在漏洞的版本中，当传入
传入"//../foo" 和 "\\..\foo"，他们处理后的结果是相同的值，即在Apache Commons IO 2.7之前的版本中，调用方法时不会处理../../ 目录穿越问题，如果开发者依赖这个来检测文件名，
可能导致存在安全隐患。

## 影响版本：
Apache Commons IO < 2.7

## 漏洞等级：中危

## 举证危害

例如：当WEB应用开发者，使用FileNameUtils.normalize 来对输入的文件命进行处理，然后拼接文件名到目录后进行文件保存，这个时候就存在安全隐患。


```
String fileName = "../../etc/passwd" ;            // 用户传入的可控参数，比如：../../etc/passwd
fileName = FileNameUtils.normalize(fileName);    // 处理后，文件名还是../../etc/passwd
           
if (fileName != null) {
    File newFile = new File("/base/uploads", fileName);    // 拼接后，实际文件为：/base/uploads/../../etc/passwd 即： /etc/passwd文件
                                
    newFile = newFile.getCanonicalFile();            // 目录穿越成功

    // 对文件进行读写等操作
} else {
    // Assume malicious activity, handle error
}

```
## Issues

(IO-559)[https://issues.apache.org/jira/browse/IO-559]

## 参考

https://snyk.io/vuln/SNYK-JAVA-COMMONSIO-1277109

poc: `curl http://localhost:8080/public/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/root/.ssh/id_rsa`
