<?php
namespace app\controller;

use app\BaseController;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use think\facade\Config;

class Index extends BaseController
{
    protected $middleware = [
        'auth' => ['except' => [
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

    public function time()
    {
        return $this->getResponse(time());
    }
}
