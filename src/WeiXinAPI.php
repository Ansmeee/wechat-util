<?php

namespace Ubi\Utils;

use DOMDocument;
use Ubi\Utils\wexin\Prpcrypt;

class WeiXinAPI
{
    private $agentId;
    private $corpId;
    private $corpSecret;
    private $accessToken;
    private $httpClient;

    function __construct()
    {
        $this->httpClient = new HttpClient();
    }

    /**
     * 设置一些必要的参数
     * @param $params
     * @return $this
     */
    public function setParams(array $params)
    {
        $this->accessToken = isset($params['accessToken']) ? $params['accessToken'] : $this->accessToken;
        $this->agentId     = isset($params['agentId']) ? $params['agentId'] : $this->agentId;
        $this->corpId      = isset($params['corpId']) ? $params['corpId'] : $this->corpId;
        $this->corpSecret  = isset($params['corpSecret']) ? $params['corpSecret'] : $this->corpSecret;

        return $this;
    }

    /**
     * 获取 accessToken，开发者需要缓存 accessToken，用于后续接口的调用（注意：不能频繁调用 getAccessToken 接口，否则会受到频率拦截）。
     * 当 accessToken 失效或过期时，需要重新获取。
     * @return array|bool|string
     * [
     *      'accessToken' => '获取到的凭证，最长为512字节',
     *      'expiresIn' => '凭证的有效时间（秒）'
     * ]
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => 'data']
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken()
    {
        if (empty($this->corpId)) {
            throw new \Exception('微信 API 接口调用失败: corpId 不能为空');
        }

        if (empty($this->corpSecret)) {
            throw new \Exception('微信 API 接口调用失败: corpSecret 不能为空');
        }

        $api = $this->getAPI('accessToken');
        if (empty($api)) {
            throw new \Exception('微信 API 接口调用失败: 无法获取 accessToken 接口请求地址');
        }

        $params = [
            'corpid'     => $this->corpId,
            'corpsecret' => $this->corpSecret
        ];

        $originResponse = $this->httpClient->get($api, $params);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }
        $data = [
            'accessToken' => $response->access_token,
            'expiresIn'   => $response->expires_in,
        ];

        return ['code' => 1, 'msg' => 'ok', 'data' => $data];
    }

    /**
     * 解密回调信息，并进行密文比对验证，通过才可以进行之后的调用
     * @param $params  ['token', 'encodingAesKey', 'msgSignature', 'timestamp', 'nonce', 'encrypt']
     * @return mixed
     * @throws \Exception
     */
    public function decryptCallBackMsg(array $params)
    {
        if (strlen($params['encodingAesKey']) != 43) {
            throw new \Exception("微信 API 接口调用失败: encodingAesKey 不合法");
        }

        if (empty($params['token']) || empty($params['encodingAesKey']) || empty($params['msgSignature']) || empty($params['timestamp']) || empty($params['nonce']) || empty($params['encrypt'])) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数，token: {$params['token']}, encodingAesKey: {$params['encodingAesKey']}, msgSignature: {$params['msgSignature']}，timestamp: {$params['timestamp']}，nonce: {$params['nonce']}，encrypt: {$params['encrypt']}");
        }

        // 验证签名是否合法
        if (!$this->verifySignature($params)) {
            throw new \Exception("微信 API 接口调用失败: 回调消息签名验证失败");
        }

        // 解密加密之后的消息内容
        $decryptMsg = $this->decryptMsg($params['encodingAesKey'], $params['encrypt'], $this->corpId);
        return $decryptMsg;
    }

    /**
     * 解析用户发送的消息内容
     * @param $params  ['token', 'encodingAesKey', 'msgSignature', 'timestamp', 'nonce', 'data']
     * @return mixed
     * @throws \Exception
     */
    public function decryptUserMsg(array $params)
    {
        if (strlen($params['encodingAesKey']) != 43) {
            throw new \Exception("微信 API 接口调用失败: encodingAesKey 不合法");
        }

        if (empty($params['token']) || empty($params['encodingAesKey']) || empty($params['msgSignature']) || empty($params['timestamp']) || empty($params['nonce']) || empty($params['data'])) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数，token: {$params['token']}, encodingAesKey: {$params['encodingAesKey']}, msgSignature: {$params['msgSignature']}，timestamp: {$params['timestamp']}，nonce: {$params['nonce']}，data: {$params['data']}");
        }

        $encrypt = $this->parseEncryptFromXML($params['data']);
        if (!$encrypt) {
            throw new \Exception("微信 API 接口调用失败: 消息内容解析失败");
        }

        $params['encrypt'] = $encrypt;

        // 验证签名是否合法
        if (!$this->verifySignature($params)) {
            throw new \Exception("微信 API 接口调用失败: 回调消息签名验证失败");
        }

        // 解密加密之后的消息内容
        $decryptMsg = $this->decryptMsg($params['encodingAesKey'], $params['encrypt'], $this->corpId);
        $xmlMsg     = simplexml_load_string($decryptMsg);

        $message = $this->getMessage($xmlMsg);
        return $message;
    }

    /**
     * 获取企业微信服务器的ip段
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => ["101.226.103.*", "101.226.62.*"]]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getCallbackIP()
    {
        return $this->getIP('getCallbackIP');
    }

    /**
     * 获取企业微信API域名IP段
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => ["182.254.11.176", "182.254.78.66"]]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAPIDomainIP()
    {
        return $this->getIP('getAPIDomainIP');
    }

    /**
     * @param  string  $type  ['image', 'voice', 'video', 'file']
     * @param  string  $mediaPath
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function uploadMedia(string $type, string $mediaPath)
    {
        if (empty($type)) {
            throw new \Exception("微信 API 接口调用失败: 素材类型为空");
        }

        if (!in_array($type, ['image', 'voice', 'video', 'file'])) {
            throw new \Exception("微信 API 接口调用失败: 素材类型不合法，仅支持（image, voice, video, file）");
        }

        if (!file_exists($mediaPath)) {
            throw new \Exception("微信 API 接口调用失败: 素材不存在");
        }

        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        $api = $this->getAPI('uploadMedia');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取素材上传接口请求地址");
        }

        $params = [
            'access_token' => $accessToken,
            'type'         => $type
        ];

        $formData = [
            [
                'name'       => $type,
                'contents'   => fopen($mediaPath, 'r'),
                'filename'   => pathinfo($mediaPath, PATHINFO_BASENAME),
                'filelength' => filesize($mediaPath)
            ]
        ];

        $originResponse = $this->httpClient->postFormData($api, $formData, $params, true);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        $data = ['mediaId' => $response->media_id, 'createdAt' => $response->created_at];
        return ['code' => 1, 'msg' => 'ok', 'data' => $data];
    }

    /**
     * 获取临时素材
     * @param $mediaId
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => 'filePath']
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getMedia(string $mediaId)
    {
        if (empty($mediaId)) {
            throw new \Exception("微信 API 接口调用失败: mediaId 为空");
        }

        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        $api = $this->getAPI('getMedia');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取素材下载接口请求地址");
        }

        $params = [
            'access_token' => $accessToken,
            'media_id'     => $mediaId
        ];


        $originResponse = $this->httpClient->get($api, $params);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        $headers                = $this->httpClient->getResponseHeaders();
        $contentDispositions    = $headers['Content-disposition'];
        $contentDisposition     = $contentDispositions[0];
        $contentDispositionInfo = explode(';', $contentDisposition);
        $fileInfo               = explode('=', trim(end($contentDispositionInfo)));
        $fileName               = trim(end($fileInfo), '"');

        $time        = time();
        $tmpFilePath = "/tmp/{$time}_{$fileName}";
        $res         = file_put_contents($tmpFilePath, $response);
        if ($res) {
            return ['code' => 1, 'msg' => 'ok', 'data' => $tmpFilePath];
        }

        return ['code' => 0, 'msg' => '文件获取失败，请重试'];
    }

    /**
     * @param  array  $message  ['code' => 'response_code', 'text' => 'button_text']
     * @param $users  [user1, user2, user3] | @all
     * @return array
     * @throws \Exception
     */
    public function updateTemplateBTN(array $message, $users)
    {
        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        if (empty($message)) {
            throw new \Exception("微信 API 接口调用失败: 消息内容为空");
        }

        $messageInfo = [
            'userids'       => is_array($users) ? $users : explode(',', $users),
            'atall'         => $users == '@all' ? 1 : 0,
            'agentid'       => $this->agentId,
            'response_code' => $message['code'] ?? '',
            'button'        => ['replace_name' => $message['text'] ?? '']
        ];

        $api = $this->getAPI('updateTemplateCard');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取发送消息接口请求地址");
        }

        $params = [
            'access_token' => $accessToken
        ];

        $originResponse = $this->httpClient->post($api, $params, $messageInfo);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        $data = [
            'invaliduser' => $response->invalid_userids
        ];

        return ['code' => 1, 'msg' => 'ok', 'data' => $data];
    }

    private function makeBTNMessage(array $messageInfo, $users)
    {
        $message = [
            'touser'        => is_array($users) ? implode('|', $users) : $users,
            'msgtype'       => 'template_card',
            'agentid'       => $this->agentId,
            'template_card' => [
                'card_type'               => 'button_interaction',
                'task_id'                 => $messageInfo['task_id'] ? ($messageInfo['task_id'].'_'.md5(time())) : '',
                'source'                  => ['desc' => $messageInfo['title'] ?? '',],
                'main_title'              => ['title' => $messageInfo['subTitle'] ?? '',],
                'sub_title_text'          => $messageInfo['subText'] ?? '',
                'horizontal_content_list' => $messageInfo['list'] ?? [],
                'button_list'             => $messageInfo['buttonList']
            ]
        ];

        if ($messageInfo['cardUrl']) {
            $message['template_card']['card_action'] = [
                'type' => 1,
                'url'  => $messageInfo['cardUrl'] ?? ''
            ];
        }

        return $message;
    }

    private function sendButtonMessageToUsers(array $messageInfo, $users)
    {
        $message = $this->makeBTNMessage($messageInfo, $users);
        return $this->sendMessage($message);
    }

    private function makeTPLTextMessage(array $messageInfo, $users)
    {
        $message = [
            'touser'        => is_array($users) ? implode('|', $users) : $users,
            'msgtype'       => 'template_card',
            'agentid'       => $this->agentId,
            'template_card' => [
                'card_type'               => 'text_notice',
                'task_id'                 => $messageInfo['task_id'] ? ($messageInfo['task_id'].'_'.md5(time())) : '',
                'source'                  => ['desc' => $messageInfo['title'] ?? '',],
                'main_title'              => [
                    'title' => $messageInfo['subTitle'] ?? ''
                ],
                'sub_title_text'          => $messageInfo['subText'] ?? '',
                'horizontal_content_list' => $messageInfo['list'] ?? [],
                'card_action'             => [
                    'type' => 1,
                    'url'  => $messageInfo['cardUrl'] ?? ''
                ]
            ]
        ];

        return $message;
    }

    private function sendTPLTextMessageToUsers(array $messageInfo, $users)
    {
        $message = $this->makeTPLTextMessage($messageInfo, $users);
        return $this->sendMessage($message);
    }

    private function makeTPLNewsMessage(array $messageInfo, $users)
    {
        $message = [
            'touser'        => is_array($users) ? implode('|', $users) : $users,
            'msgtype'       => 'template_card',
            'agentid'       => $this->agentId,
            'template_card' => [
                'card_type'  => 'news_notice',
                'task_id'    => $messageInfo['task_id'] ? ($messageInfo['task_id'].'_'.md5(time())) : '',
                'source'     => ['desc' => $messageInfo['title'] ?? '',],
                'main_title' => ['title' => $messageInfo['subTitle'] ?? '', 'desc' => $messageInfo['subText']],
                'card_image' => [
                    'url'          => $messageInfo['imageUrl'] ?? '',
                    "aspect_ratio" => $messageInfo['imageRatio'] ?? 1.3
                ]
            ]
        ];

        if ($messageInfo['cardUrl']) {
            $message['template_card']['card_action'] = [
                'type' => 1,
                'url'  => $messageInfo['cardUrl'] ?? ''
            ];
        }

        return $message;
    }

    private function sendTPLNewsMessageToUsers(array $messageInfo, $users)
    {
        $message = $this->makeTPLNewsMessage($messageInfo, $users);
        return $this->sendMessage($message);
    }

    public function sendTemplateMessageToUsers(array $messageInfo, $users)
    {
        if ($messageInfo['template'] == 'button') {
            return $this->sendButtonMessageToUsers($messageInfo, $users);
        }

        if ($messageInfo['template'] == 'news') {
            return $this->sendTPLNewsMessageToUsers($messageInfo, $users);
        }

        if ($messageInfo['template'] == 'text') {
            return $this->sendTPLTextMessageToUsers($messageInfo, $users);
        }
    }

    /**
     * 向指定用户发送文本消息
     * @param $message
     * @param $users  [user1, user2, user3] | @all
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToUsers(string $message, $users, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', $users, [], [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 向指定部门发送文本消息
     * @param $message
     * @param $parties  [party1, party2]
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToParties(string $message, array $parties, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', [], $parties, [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 向指定标签的成员发送文本消息
     * @param $message
     * @param $tags  [tag1, tag2]
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToTags(string $message, array $tags, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', [], [], $tags, $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 给指定用户发送 markdown 格式的消息
     * @param $message
     * @param $users  [user1, user2, user3] | @all
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToUsers(string $message, $users, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', $users, [], [], $isSafe);
        return $this->sendMessage($messageInfo);
    }

    /**
     * 给指定部门发送 markdown 格式的消息
     * @param $message
     * @param $parties  [party1, party2]
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToParties(string $message, array $parties, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', [], $parties, [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return ['invalidparty' => $response['invalidparty']];
    }

    /**
     * 给指定标签的用户发送 markdown 格式的消息
     * @param $message
     * @param $tags  [tag1, tag2]
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToTags(string $message, array $tags, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', [], [], $tags, $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return ['invalidtag' => $response['invalidtag']];
    }

    /**
     * @param  string  $mediaId
     * @param $users  [user1, user2, user3] | @all
     * @param  bool  $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendImageMessageToUsers(string $mediaId, $users, $isSafe = false)
    {
        if (empty($mediaId)) {
            throw new \Exception("微信 API 接口调用失败: mediaId 为空");
        }

        if (empty($users)) {
            throw new \Exception("微信 API 接口调用失败: 消息接收人 为空");
        }

        $messageInfo = $this->makeMessage($mediaId, 'image', $users, [], [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    public function sendNewsMessageToUsers(array $message, $users)
    {
        $messageInfo = $this->makeMessage($message, 'text', $users, [], [], 0);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    private function makeMessage($message, $type = 'text', $users, $parties, $tags, $isSafe)
    {
        $messageInfo = [
            'touser'  => is_array($users) ? implode('|', $users) : $users,
            'toparty' => implode('|', $parties),
            'totag'   => implode('|', $tags),
            'msgtype' => $type,
            'agentid' => $this->agentId,
            'safe'    => $isSafe ? 1 : 0
        ];

        if ($type === 'text') {
            $messageInfo['text'] = ['content' => $message];
            return $messageInfo;
        }

        if ($type === 'markdown') {
            $messageInfo['markdown'] = ['content' => $message];
            return $messageInfo;
        }

        if ($type === 'image') {
            $messageInfo['image'] = ['media_id' => $message];
            return $messageInfo;
        }

        if ($type === 'news') {
            $messageInfo['news'] = [
                'articles' => [
                    [
                        'title'       => $message['content']['title'] ?? '',
                        'description' => $message['content']['text'] ?? '',
                        'picurl'      => $message['content']['imageUrl'] ?? '',
                    ]
                ]
            ];

            return $messageInfo;
        }

        return $messageInfo;
    }

    public function createMenu(array $params = [])
    {
        $accessToken = $params['accessToken'] ?? '';
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        $body = $params['menu'] ?? [];
        if (empty($body)) {
            throw new \Exception("微信 API 接口调用失败: 菜单配置为空");
        }

        $api = $this->getAPI('createMenu');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取创建菜单接口请求地址");
        }

        $params = [
            'access_token' => $accessToken,
            'agentid'      => $params['agentid'] ?? ''
        ];

        $originResponse = $this->httpClient->postJson($api, $params, $body);
        $response       = $this->handleResponse($originResponse);
        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        return ['code' => 1, 'msg' => 'ok'];
    }

    private function sendMessage($message)
    {
        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        if (empty($message)) {
            throw new \Exception("微信 API 接口调用失败: 消息内容为空");
        }

        $api = $this->getAPI('sendMessage');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取发送消息接口请求地址");
        }

        $params = [
            'access_token' => $accessToken
        ];

        $originResponse = $this->httpClient->postJson($api, $params, $message);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        $data = [
            'invaliduser'  => isset($response->invaliduser) ? explode('|', $response->invaliduser) : [],
            'invalidparty' => isset($response->invalidparty) ? explode('|', $response->invalidparty) : [],
            'invalidtag'   => isset($response->invalidtag) ? explode('|', $response->invalidtag) : [],
        ];

        return ['code' => 1, 'msg' => 'ok', 'data' => $data];
    }

    /**
     * @param  string  $type
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => 'data']
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function getIP($type = 'getAPIDomainIP')
    {
        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数 accessToken");
        }

        $api = $this->getAPI($type);
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取 {$type} 接口请求地址");
        }

        $params = [
            'access_token' => $accessToken
        ];

        $originResponse = $this->httpClient->get($api, $params);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        return ['code' => 1, 'msg' => 'ok', 'data' => $response->ip_list];
    }

    private function verifySignature($params)
    {
        $encryptArr = [$params['encrypt'], $params['token'], $params['timestamp'], $params['nonce']];

        sort($encryptArr, SORT_STRING);
        $encryptStr      = implode('', $encryptArr);
        $devMsgSignature = sha1($encryptStr);

        $msgSignature = $params['msgSignature'];
        return $msgSignature === $devMsgSignature;
    }

    private function decryptMsg($encodingAesKey, $encrypt, $receiveId)
    {
        $decrypter = new Prpcrypt($encodingAesKey);
        $result    = $decrypter->decrypt($encrypt, $receiveId);

        if (!is_array($result) || count($result) != 2) {
            throw new \Exception("微信 API 接口调用失败: 消息解密失败");
        }

        if ($result[0] != 0) {
            throw new \Exception("微信 API 接口调用失败: 消息解密失败");
        }

        return $result[1];
    }

    private function handleResponse($response)
    {
        if (isset($response->errcode) && 0 != $response->errcode) {

            // accessToken 过期，需要重新获取
            if (40014 == $response->errcode) {
                return false;
            }

            throw new \Exception("微信 API 接口调用失败: {$response->errmsg}");
        }

        return $response;
    }

    private function getMessage($xmlMsg)
    {
        $messageType             = (string) $xmlMsg->MsgType;
        $message['fromUserName'] = (string) $xmlMsg->FromUserName;
        $message['toUserName']   = (string) $xmlMsg->ToUserName;
        $message['createTime']   = (string) $xmlMsg->CreateTime;
        $message['agentId']      = (string) $xmlMsg->AgentID;
        $message['id']           = (string) $xmlMsg->MsgId;
        $message['type']         = $messageType;

        $content = [];
        if ($messageType == 'text') {
            $content['text'] = (string) $xmlMsg->Content;
        }

        if ($messageType == 'event') {
            $content['type']     = (string) $xmlMsg->Event;
            $content['key']      = (string) $xmlMsg->EventKey;
            $content['id']       = (string) $xmlMsg->TaskId;
            $content['code']     = (string) $xmlMsg->ResponseCode;
            $content['cardType'] = (string) $xmlMsg->CardType;
        }

        $message['content'] = $content;
        return $message;
    }

    private function parseEncryptFromXML($xmlData)
    {
        $xml = new DOMDocument();
        $xml->loadXML($xmlData);
        $array   = $xml->getElementsByTagName('Encrypt');
        $encrypt = $array->item(0)->nodeValue;
        return $encrypt;
    }

    private function getAPI($pathName)
    {
        if (empty($pathName)) {
            return false;
        }

        $apiArr = [
            'accessToken'        => 'cgi-bin/gettoken', // 获取 accessToken
            'getCallbackIP'      => 'cgi-bin/getcallbackip', // 获取企业微信服务器的 ip 段
            'getAPIDomainIP'     => 'cgi-bin/get_api_domain_ip', // 获取企业微信API域名IP段
            'sendMessage'        => 'cgi-bin/message/send', // 发送应用消息
            'uploadMedia'        => 'cgi-bin/media/upload', // 上传临时素材
            'getMedia'           => 'cgi-bin/media/get', // 获取临时素材
            'updateTemplateCard' => 'cgi-bin/message/update_template_card', // 更新模板消息内容
            'createMenu'         => 'cgi-bin/menu/create', // 自定义菜单接口
        ];

        $host = "https://qyapi.weixin.qq.com";

        $path = $apiArr[$pathName];
        if (empty($path)) {
            return false;
        }

        return "{$host}/{$path}";
    }
}

