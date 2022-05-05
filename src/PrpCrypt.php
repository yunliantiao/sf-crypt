<?php

namespace Txtech\SfCrypt;

use Exception;

/**
 * PrpCrypt class
 *
 * 提供接收和推送给公众平台消息的加解密接口.
 */
class PrpCrypt
{
    /** @var false|string */
    public string|false $key;

    /**
     * @param $k
     */
    public function __construct($k)
    {
        $this->key = base64_decode(str_replace(" ", "+", $k . "="));
    }

    /**
     * 对明文进行加密
     * @param string $text 需要加密的明文
     * @return array 加密后的密文
     */
    public function encrypt(string $text, $appid): array
    {
        try {
            //获得16位随机字符串，填充到明文之前
            $random = $this->getRandomStr();
            $text = $random . pack("N", strlen($text)) . $text . $appid;
            $iv = substr($this->key, 0, 16);
            $pkc_encoder = new PKCS7Encoder;
            $text = $pkc_encoder->encode($text);
            $encrypted = openssl_encrypt($text, 'AES-256-CBC', $this->key, OPENSSL_NO_PADDING, $iv);

            return [ErrorCode::$OK, base64_encode($encrypted)];
        } catch (Exception $e) {
            return [ErrorCode::$EncryptAESError, null];
        }
    }

    /**
     * 对密文进行解密
     * @param string $encrypted 需要解密的密文
     * @return array 解密得到的明文
     */
    public function decrypt(string $encrypted, $appid): array
    {
        try {
            $ciphertext_dec = base64_decode($encrypted);
            $iv = substr($this->key, 0, 16);
            $decrypted = openssl_decrypt($ciphertext_dec, 'AES-256-CBC', $this->key, OPENSSL_NO_PADDING, $iv);
        } catch (Exception $e) {
            return [ErrorCode::$DecryptAESError, null];
        }

        try {
            //去除补位字符
            $pkc_encoder = new PKCS7Encoder;
            $result = $pkc_encoder->decode($decrypted);
            //去除16位随机字符串,网络字节序和AppId

            $content = substr($result, 16, strlen($result));
            $len_list = unpack("N", substr($content, 0, 4));
            $xml_len = $len_list[1];
            $xml_content = substr($content, 4, $xml_len);
            $from_appid = substr($content, $xml_len + 4);
        } catch (Exception $e) {
            return [ErrorCode::$IllegalBuffer, null];
        }
        if ($from_appid != $appid)
            return [ErrorCode::$ValidateAppidError, null];
        return [0, $xml_content];
    }


    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    public function getRandomStr()
    {
        $str = '';
        $str_pol = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }
}
