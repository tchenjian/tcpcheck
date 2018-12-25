<?php
/*
作者：聽風 		QQ：2049100
魔改：逍遥龙		QQ：860885129

v0.01 更新摘要
1.增加对nginx支持（即免flush();比原版本卡,呵呵...）
*/

//可优化 根据ip类型具体链接,非只有ip   fsockopen
$ip = @trim($_POST['ip'])?trim($_POST['ip']):'';
if($ip){
    $re = check_ip($ip);
    if($re['type']=='error'){
        die('IP error');
    }
    $ip = $re['ip'];
    //格式 以,隔开 eg: 8080,3306
    $ports = explode(',',str_replace(" ", "", $a=str_replace("，",",",$_POST['ports'])));
    //端口号去重
    $ports = array_unique($ports);
    //端口结果展示
    $list = array();
    //错误信息收集
    $ERR = array();
    foreach($ports as $port){
        if(check_port($ip,$port,$timeout=1)){
            $list[$port] = true;
        }else{
            $list[$port]= false;
        }
    }
    //echo '<pre>';print_r($list);die;
}

function check_port($ip,$port,$timeout=30) {
    global $ERR;
    $conn = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    if ($conn) {
        fclose($conn);
        return true;
    }else{
        $ERR[$ip.':'.$port] = iconv('gbk','utf-8',"$errstr ($errno)");
    }
}

/**
 * 检查ip
 * @param string $ip 需要检查的ip
 * return array 检查结果  ip 检查的ip type ip类型
 * type: IPv4 IPv6 ReservedIP PrivateIP(私有IP) error(不合格IP)
 * */
function check_ip($ip){
    //判断是否是合法IP
    if(filter_var($ip, FILTER_VALIDATE_IP)) {//IPv4，IPv6，私有和保留范围IP
        //FILTER_FLAG_NO_PRIV_RANGE
        //  无法验证以下私有IPv4范围：10.0.0.0/8 , 172.16.0.0/12 和 192.168.0.0/16
        //  无法验证从FD或FC开始的IPv6地址。
        //FILTER_FLAG_NO_RES_RANGE
        //  无法验证以下保留的IPv4范围：0.0.0.0/8 , 169.254.0.0/16 , 127.0.0.0/8 和 240.0.0.0/4
        //  无法验证以下保留的IPv6范围：::1/128 ，::/128，::ffff:0:0/96 和 fe80::/10
        //仅IPv4（例如120.138.20.36）
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_IPV4)) {
            return $result = array(
                'ip'=>$ip,
                'type'=>'IPv4'
            );
        }
        //仅IPv6
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_IPV6)) {
            return $result = array(
                'ip'=>$ip,
                'type'=>'IPv6'
            );
        }
        //排除私有的,使用FILTER_FLAG_NO_PRIV_RANGE标志
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
            //127.X.X.X是保留地址，用做循环测试用的。
            //169.254.X.X是保留地址。如果你的IP地址是自动获取IP地址，而你在网络上又没有找到可用的DHCP服务器。就会得到其中一个IP
            return $result = array(
                'ip'=>$ip,
                'type'=>'ReservedIP'
            );
        }
        //排除存在大量保留的IP地址范围,使用FILTER_FLAG_NO_RES_RANGE标志
        if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
            //私有地址（所谓的私有地址就是在互联网上不使用，而被用在局域网络中的地址）。
            //10.0.0.0-10.255.255.255
            //172.16.0.0—172.31.255.255
            //192.168.0.0-192.168.255.255
            return $result = array(
                'ip'=>$ip,
                'type'=>'PrivateIP'
            );
        }
    }
    return $result = array(
        'ip'=>$ip,
        'type'=>'error'
    );
}

header('Content-Type: text/html; charset=utf-8');
error_reporting(0);
$timeout = 1; //超时时间
function is_ip($gonten) {
    $ip = explode(".", $gonten);
    for ($i = 0; $i < count($ip); $i++) {
        if ($ip[$i] > 255) {
            return (0);
        }
    }
    return ereg("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", $gonten, $regs);
}
?>
<!DOCTYPE HTML>
<html>
    
    <head>
        <meta charset="utf-8" />
        <title>TCP端口扫描 -- Ro研究手记Q群专用</title>
        <link rel="stylesheet" href="css/style.css" type="text/css" />
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css">
        <script src="js/jquery.js"></script>
        <script src="js/custom.js"></script>
    </head>
    
    <body>
        <div class="accordion-wrap">
            <div class="accordion">	<a href="javascript:void(0)"><i class="fa fa-cogs"></i> TCP端口扫描 -- Ro研究手记Q群专用</a>

                <div class="nav">
                    <div class="chat">
                        <form method='post'>
                            <input type="text" name='ip' placeholder="IP地址" style="height:25px" />
                            <br>
                            <br>
							<textarea class="SMSearTxt WrapHid" name="ports" size="90">80,888,6900,5121,6121,8080,8866,21,23,443,69,22,25,3389,1433</textarea>
							<button class="rkmd-btn btn-lightBlue ripple-effect" type='submit' name='submit' ><i class="fa fa-cogs"></i>开始扫描</button>
							<br>
							<br>
							<textarea class="SMSearTxt WrapHid" size="90">80,888,6900,5121,6121,8080,8866,3128,8081,9080,1080,21,23,443,69,22,25,110,7001,9090,3389,1521,1158,2100,1433</textarea>
							</form>
                        <?php
        if(!empty($list)){
            echo '<div class="callchat comm-chat"><span>端口扫描：'.$ip.'</span></div>';
			foreach ($ports as $port){
				if( $list[$port]){
						echo ' <div class="callchat comm-chat"><span>'.$port.' --> <font color="green"><i class="fa fa-check" aria-hidden="true"></i>开启</font></span></div>';
                }else{
						echo ' <div class="callchat comm-chat"><span>'.$port.' --> <font color="red"><i class="fa fa-times" aria-hidden="true"></i>关闭</font></span></div>';
                }
            }
            //错误提示
            /*if(!empty($ERR)){
                $err_str = '<br/>ERROR:<br/>';
                foreach ($ERR as $k=>$v){
                    $err_str .= $k.':'.$v.'<br/>';
                }
                echo $err_str;
            }*/
        }
    ?>     
                        
					</div>
				</div>
				<a href="javascript:void(0)"><i class="fa fa-code-fork"></i>&nbsp;工具简介</a>
				<div class="nav profile">
					
					<div class="introduction">
					通过该工具可以扫描常用的端口和指定的端口是否开放。<br>

					常用端口号：<br>

					代理服务器常用以下端口：<br>

					（1）. HTTP协议代理服务器常用端口号：80/8080/3128/8081/9080<br>

					（2）. SOCKS代理协议服务器常用端口号：1080<br>

					（3）. FTP（文件传输）协议代理服务器常用端口号：21<br>

					（4）. Telnet（远程登录）协议代理服务器常用端口：23<br>
					<br>
					<br>

					HTTP服务器，默认的端口号为80/tcp（木马Executor开放此端口）；<br>

					HTTPS（securely transferring web pages）服务器，默认的端口号为443/tcp 443/udp；<br>

					Telnet（不安全的文本传送），默认端口号为23/tcp（木马Tiny Telnet Server所开放的端口）；<br>

					FTP，默认的端口号为21/tcp（木马Doly Trojan、Fore、Invisible FTP、WebEx、WinCrash和Blade Runner所开放的端口）；<br>

					TFTP（Trivial File Transfer Protocol ），默认的端口号为69/udp；<br>

					SSH（安全登录）、SCP（文件传输）、端口重定向，默认的端口号为22/tcp；<br>

					SMTP Simple Mail Transfer Protocol (E-mail)，默认的端口号为25/tcp（木马Antigen、Email Password Sender、Haebu Coceda、Shtrilitz Stealth、WinPC、WinSpy都开放这个端口）；<br>

					POP3 Post Office Protocol (E-mail) ，默认的端口号为110/tcp；<br>

					WebLogic，默认的端口号为7001；<br>

					WebSphere应用程序，默认的端口号为9080；<br>

					WebSphere管理工具，默认的端口号为9090；<br>

					JBOSS，默认的端口号为8080；<br>

					TOMCAT，默认的端口号为8080；<br>

					WIN2003远程登陆，默认的端口号为3389；<br>

					Symantec AV/Filter for MSE ,默认端口号为 8081；<br>

					Oracle 数据库，默认的端口号为1521；<br>

					ORACLE EMCTL，默认的端口号为1158；<br>

					Oracle XDB（ XML 数据库），默认的端口号为8080；<br>

					Oracle XDB FTP服务，默认的端口号为2100；<br>

					MS SQL*SERVER数据库server，默认的端口号为1433/tcp 1433/udp；<br>

					MS SQL*SERVER数据库monitor，默认的端口号为1434/tcp 1434/udp；<br>

					QQ，默认的端口号为1080/udp<br>
					</div>
				</div>

			</div>
		</div>
		
	</body>
</html>

