<?php

namespace Ubi\Utils\wexin;

class Prpcrypt
{
    public $key = null;
    public $iv  = null;

    /**
     * Prpcrypt constructor.
     * @param $k
     */
    public function __construct($k)
    {
        $this->key = base64_decode($k . '=');
        $this->iv  = substr($this->key, 0, 16);

    }

    /**
     * 解密
     *
     * @param $encrypted
     * @param $receiveId
     * @return array
     */
    public function decrypt($encrypted, $receiveId)
    {
        //解密
        if (function_exists('openssl_decrypt')) {
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, OPENSSL_ZERO_PADDING, $this->iv);
        } else {
            $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->key, base64_decode($encrypted), MCRYPT_MODE_CBC, $this->iv);
        }

        $result = $this->decode($decrypted);
        if (strlen($result) < 16) {
            return [];
        }

        //拆分
        $content        = substr($result, 16, strlen($result));
        $len_list       = unpack('N', substr($content, 0, 4));
        $xml_len        = $len_list[1];
        $xml_content    = substr($content, 4, $xml_len);
        $from_receiveId = substr($content, $xml_len + 4);

        if ($from_receiveId != $receiveId) {
            throw new \Exception('微信 API 接口调用失败: 回调消息解密失败，接受人不一致');
        }

        return [0, $xml_content];
    }

    function decode($text)
    {

        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }
}
