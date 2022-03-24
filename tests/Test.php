<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\HttpClient;

$http = new HttpClient();

$url = "http://local.visual.com/rest/base/userinfo";
$res = $http->get($url);

var_dump($res);
