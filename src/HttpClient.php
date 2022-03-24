<?php

namespace Ubi\Utils;

use GuzzleHttp\Client;

/**
 * Class HttpClient
 * http 请求公共类
 * 对http常用的4个method进行了封装
 * 对于post， 可以直接使用post, 不过更加建议使用更为清晰的postFormData、postJson
 * HttpClient
 *
 * @package App\Utils
 */
class HttpClient
{
    private $timeout         = 30;
    private $connectTimeOut  = 30;
    private $options         = [];
    private $responseHeaders = [];

    function __construct()
    {
        $this->resetResponse();
    }

    private function resetResponse(){
        $this->responseHeaders = [];
    }
    /**
     * @param $uri
     * @param array $params
     * @param string $method
     * @param array $body
     * @param bool $isJson
     * @param bool $isMultiFile
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function requestApi($uri, $params = [], $method = 'GET', $body = [], $isJson = true, $isMultiFile = false, $auth = [])
    {
        // 先初始化返回头
        $this->resetResponse();

        $client  = new Client(array_merge([], ['base_uri' => $uri], $auth));
        $options = ['query' => array_merge([], $params)];

        // 如果不是 get 方法，需要拼接 body
        if ($method != 'GET' && $body) {
            if ($isJson) {
                $options['json'] = array_merge([], $body);
            } elseif ($isMultiFile) {
                $items = [];
                // multi file的传输格式需要定制
                foreach ($body as $item) {
                    $items[] = [
                        'name'       => isset($item['name']) ? $item['name'] : '',
                        'contents'   => isset($item['contents']) ? $item['contents'] : '',
                        'filename'   => isset($item['filename']) ? $item['filename'] : '',
                        'filelength' => isset($item['filelength']) ? $item['filelength'] : '',
                        'headers'    => [
                            'content-type' => 'multipart/form-data',
                            'accept'       => 'application/json'
                        ]
                    ];
                }

                $options['multipart'] = $items;
            } else {
                $options['form_params'] = array_merge([], $body);
            }
        }

        $options['timeout']         = $this->timeout;
        $options['connect_timeout'] = $this->connectTimeOut;
        $options                    = array_merge($options, $this->options);
        try {
            $response = $client->request($method, $uri, $options);
            $content  = $response->getBody()->getContents();
            $json     = json_decode($content);

            $this->setResponseHeaders($response->getHeaders());

            if ($json && $content != $json) {
                return $json;
            }

            return $content;
        } catch (\Exception $exception) {
            throw new \Exception($exception->getMessage());
        }
    }

    public function getResponseHeaders()
    {
        return $this->responseHeaders;
    }

    private function setResponseHeaders($headers)
    {
        $this->responseHeaders = $headers;
    }

    /**
     * 设置请求超时时间
     * @param $seconds
     * @return $this
     */
    public function setTimeout($seconds)
    {
        $this->timeout = $seconds;

        return $this;
    }

    /**
     * 设置等待服务器响应超时的最大值
     * @param $seconds
     * @return $this
     */
    public function setConnectTimeout($seconds)
    {
        $this->connectTime = $seconds;

        return $this;
    }

    /**
     * @param $url
     * @param $params
     * @param $body
     * @param bool $isJson
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function post($url, $params, $body, $isJson = true)
    {
        return $this->requestApi($url, $params, 'POST', $body, $isJson);
    }

    /**
     * @param $url
     * @param $params
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function get($url, $params = [])
    {
        return $this->requestApi($url, $params, 'get');
    }

    /**
     * @param $url
     * @param $params
     * @param $body
     * @param bool $isJson
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function put($url, $params, $body, $isJson = true)
    {
        return $this->requestApi($url, $params, 'PUT', $body, $isJson);
    }

    /**
     * @param $url
     * @param $params
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function delete($url, $params)
    {
        return $this->requestApi($url, $params, 'get');
    }


    /**
     * 发送formdata
     * guzzle 在发送formdata分两种情况， 默认使用的是： x-www-form-urlencoded 在guzzle中对应的是参数form-data
     * 如果有文件，只能使用 form-data 的方式，对应的是guzzle中 multipart 参数
     * @param $url
     * @param $queryArray
     * @param $formData array key value数组
     * @param bool $isMultiFile 传输的数据是否包含文件
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function postFormData($url, $formData, $queryArray = [], $isMultiFile = false)
    {
        return $this->requestApi($url, $queryArray, 'POST', $formData, false, $isMultiFile);
    }

    /**
     * @param $url
     * @param $params
     * @param $jsonArray
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function postJson($url, $params, $jsonArray, $auth = [])
    {
        $this->resetResponse();

        $client  = new Client(array_merge([], ['base_uri' => $url], $auth));

        try {
            $response = $client->request('POST', $url, [
                'query' => $params,
                'body' => json_encode($jsonArray, JSON_UNESCAPED_UNICODE),
                'headers' => ['Content-Type' => 'application/json']
            ]);

            $content  = $response->getBody()->getContents();
            $json     = json_decode($content);

            $this->setResponseHeaders($response->getHeaders());

            if ($json && $content != $json) {
                return $json;
            }

            return $content;
        } catch (\Exception $exception) {
            throw new \Exception($exception->getMessage());
        }
    }

    public function setOptions($options)
    {
        $this->options = $options;

        return $this;
    }
}
