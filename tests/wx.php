<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;


$params = [
    'corpId'      => 'ww52f8d8da8cab19eb',
    'corpSecret'  => 'XRNQP0IAZO--LqWnTAydeZ64ysWv40BuLxGMgJJ2ZiU',
    'agentId'     => '1000036',
    'accessToken' => 'HFV2oTw5kfMet5XngmJBolDUvFbTH5fIoAVu4k9Y-XFgUSN1ldaHKqMCnD3Hi_HBmymHr-8RTQQ2Iq_UatuamgV7x35AdtzOJs-IidL-iXByEDQACNVpBxgNqEvCkTS6hOpdvg_MKo1I3LdU5fweUge7zQi_rZY0h5twqHhTDodpsP5WUuGG0T6MlNptaXb6OcKy-2wOiJHClYF4LdNtyQ'
];

// 返回的url验证明文
$wxcpt = new WeiXinAPI();
$wxcpt->setParams($params);


// var_dump($wxcpt->getAccessToken());

// $res = $wxcpt->uploadMedia('image', './logo.png');
// var_dump($res);

$mediaId = '3C8p1QLz8R5eEokpYC-HDIfAc4EkrsxP1rvOJhngF9EU8PiJje3Mc6xzlY7aBsYjG';

$res = $wxcpt->sendImageMessageToUsers($mediaId, 'ZhengWenJun');
var_dump($res);
