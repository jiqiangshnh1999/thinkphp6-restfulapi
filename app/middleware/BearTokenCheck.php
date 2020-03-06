<?php
declare (strict_types = 1);

namespace app\middleware;

use Closure;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Redis;
use think\Cache;
use think\facade\Db;
use think\Request;
use think\response\Json;

class BearTokenCheck
{
    /**
     * redis 连接实例
     * @var Redis
     */
    protected $redis;

    protected $responseData = [
        'success' => false,
        'code'    => 401,
        'data'    => '',
        'err_msg' => '请求非法！'
    ];

    /**
     * 注入redis实列
     * BearTokenCheck constructor.
     * @param Cache $cache
     */
    public function __construct(Cache $cache)
    {
        $this->redis = $cache->handler();
    }

    /**
     * 处理请求
     * @param Request $request
     * @param Closure $next
     * @return Json
     */
    public function handle($request, Closure $next)
    {
        $authorization = $request->header('authorization', '');

        if (preg_match('/^Bearer\s(.*+)$/s', $authorization, $match))
        {
            $token = (new Parser())->parse($match[1]);
            if ($token->verify(new Sha256(), new Key(config('jwt.public_key'))))
            {
                $userInfo = unserialize($token->getHeader('jti'));

                if (Db::name('user')->whereExists(['id' => $userInfo['id']]))
                {
                    return $next($request);
                }
            }
        }

        return  json($this->responseData, config('code.TOKEN_ILLEGAL_CODE'));
    }
}
