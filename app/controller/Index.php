<?php
namespace app\controller;

use app\BaseController;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use think\facade\Config;
use AlibabaCloud\Client\AlibabaCloud;
use AlibabaCloud\Client\Exception\ClientException;
use AlibabaCloud\Client\Exception\ServerException;

class Index extends BaseController
{
    protected $middleware = [
        'auth' => [
            'except' => [
                'save'
            ]
        ]
    ];

    public function index()
    {
        return $this->getResponse($this->request->header());
    }

    public function save(int $id)
    {
        $time = time();

        $jti = serialize([
            'id' => $id,
            'phone' => '13966668888'
        ]);

        $signer = new Sha256();
        $privateKey = new Key(Config::get('jwt.private_key'));

        $token = (new Builder())
            ->issuedBy('http://api.tp6.com')
            ->permittedFor('http://user.org')
            ->identifiedBy($jti, true)
            ->issuedAt($time)
            ->canOnlyBeUsedAfter($time + 60)
            ->expiresAt($time + 3600)
            ->withClaim('uid', $id)
            ->getToken($signer, $privateKey);

        return $this->getResponse([
            'id' => $id,
            'token' => $token->__toString()
        ]);
    }

    public function captcha()
    {
        $error = null;
        $phone = $this->request->post('phone');

        if (preg_match('/(^1[\d]{10})/', $phone, $match))
        {
            try {
                AlibabaCloud::accessKeyClient('<accessKeyId>', '<accessSecret>')
                    ->regionId('cn-hangzhou')
                    ->asDefaultClient();
            } catch (ClientException $e) {
                $error = $e->getErrorMessage() . PHP_EOL;
            }

            if (! $error)
            {
                try {
                    $result = AlibabaCloud::rpc()
                        ->product('Dysmsapi')
                        // ->scheme('https') // https | http
                        ->version('2017-05-25')
                        ->action('SendSms')
                        ->method('POST')
                        ->host('dysmsapi.aliyuncs.com')
                        ->options([
                            'query' => [
                                'RegionId' => "cn-hangzhou",
                                'PhoneNumbers' => $match[1],
                                'SignName' => "阿里云",
                                'TemplateCode' => "SMS_153055065",
                            ],
                        ])
                        ->request();

                    $result = $result->toArray();

                    if ($result['code'] = 'OK')
                    {
                        return $this->getResponse('发送成功');
                    }else{
                        $error = $result['message'];
                    }
                } catch (ClientException $e) {
                    $error = $e->getErrorMessage() . PHP_EOL;
                } catch (ServerException $e) {
                    $error = $e->getErrorMessage() . PHP_EOL;
                }
            }
        }

        if ($error)
        {
            //TODO
            //log处理
            return $this->getResponse('发送失败,请稍后再试！');
        }
    }

    public function time()
    {
        return $this->getResponse(time());
    }
}
