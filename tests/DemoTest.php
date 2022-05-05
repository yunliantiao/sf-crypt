<?php

use Txtech\SfCrypt\BizMsgCrypt;


/**
 * User : Zelin Ning(NiZerin)
 * Date : 2022/5/5
 * Time : 18:03
 * Email: i@nizer.in
 * Site : nizer.in
 * FileName: Demo.php
 */
class DemoTest extends \PHPUnit\Framework\TestCase
{
    public function testEnCrypt()
    {
        $encodingAesKey = "dcLutUPXvxDjzVDgLV0SsAI5UAxmEloNHEZVtgxnvuA";
        $token = "auth_d830f571-570a-44e7-a51a-c49b1ec6d79f_1637927849980";
        $timeStamp = "1637927849983";
        $nonce = "1637927849983";
        $appId = "76a5c52b9027505f4fcc4c358fb58211";
        $text = "{\"requestId\":\"1614077277245\",\"version\":\"\",\"customerCode\":\"ICRME00009798\",\"obj\":{\"customerOrderNo\":\"1627293897271455\"}}";

        $pc = new BizMsgCrypt($token, $encodingAesKey, $appId);

        $result = $pc->encryptMsg($text, $timeStamp, $nonce);
        $this->assertIsArray($result);

        $encrypt = "8J2XeGGpK5oEcIytFfln91CYH4VfeXpV73X7Q+O9lJFTlMr0eV4YH+6r0HpIY8pSJIPqeVqEcjFR+ZS92b9M7jnijYEh6LMkCg85XP5tDBMbbk+eWrU8++mzaa7jKI7W";
        $deResult = $pc->decryptMsg($timeStamp, $nonce, $encrypt);
        $this->assertIsArray($deResult);
    }
}