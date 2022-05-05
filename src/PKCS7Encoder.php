<?php

namespace Txtech\SfCrypt;

/**
 * PKCS7Encoder class
 *
 * 提供基于PKCS7算法的加解密接口.
 */
class PKCS7Encoder
{
    /** @var int */
    private static $block_size = 32;

    /**
     * 对需要加密的明文进行填充补位
     * @param String $text 需要进行填充补位操作的明文
     * @return string 补齐明文字符串
     */
    public function encode($text)
    {
        $text_length = strlen($text);

        $amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = PKCS7Encoder::$block_size;
        }

        $pad_chr = chr($amount_to_pad);
        $tmp = str_repeat($pad_chr, $amount_to_pad);
        return $text . $tmp;
    }

    /**
     * 对解密后的明文进行补位删除
     * @param $text String 解密后的明文
     * @return string 删除填充补位后的明文
     */
    public function decode($text)
    {
        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }
}