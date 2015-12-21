import socket
import struct
import sys 
import os
#python GetJapIP.py 125.255.0.0 125.255.255.255 >> JapUrls.txt
start_ip = sys.argv[1]
end_ip = sys.argv[2]

def Ip2Int(ip):
	return socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])
Intstart_ip = Ip2Int(start_ip)
Intend_ip = Ip2Int(end_ip)

'''
print "start_ip = "+str(Intstart_ip)
print "end_ip = "+str(Intend_ip)
print "There are "+str(Intend_ip - Intstart_ip)+" ips!"
'''
for i in range(Intstart_ip,Intend_ip):
	IP = socket.inet_ntoa(struct.pack('I',socket.htonl(i)))
	print str(IP)
	
print "There are "+str(Intend_ip - Intstart_ip)+" ips!"