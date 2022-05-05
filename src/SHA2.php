<?php

namespace Txtech\SfCrypt;

use Exception;

/**
 * sha256 class
 *
 * 消息签名方法.
 */
class SHA2
{
    /**
     * 用sha256算法生成安全签名
     * @param string $token 票据
     * @param int $timestamp 时间戳
     * @param string $nonce 随机字符串
     * @param string $encrypt_msg 密文消息
     */
    public function getSHA2(string $token, int $timestamp, string $nonce, string $encrypt_msg): array
    {
        try {
            $array = [$encrypt_msg, $token, $timestamp, $nonce];
            sort($array, SORT_STRING);
            $str = implode($array);
            return [ErrorCode::$OK, hash('sha256', $str)];
        } catch (Exception $e) {
            return [ErrorCode::$ComputeSignatureError, null];
        }
    }
}