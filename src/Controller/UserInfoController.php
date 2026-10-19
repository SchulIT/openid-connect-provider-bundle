<?php

declare(strict_types=1);

namespace Ajgarlag\Bundle\OpenIDConnectProviderBundle\Controller;

use Ajgarlag\Bundle\OpenIDConnectProviderBundle\OpenIDConnect\UserInfoResponse;
use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final readonly class UserInfoController
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private UserInfoResponse $userInfoResponse,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->tokenStorage->getToken();

        if (!$token instanceof OAuth2Token) {
            throw new UnauthorizedHttpException('oauth2', 'No OAuth2/OIDC token found.');
        }

        $claims = $this->userInfoResponse->resolveClaims($token);

        return new JsonResponse($claims, Response::HTTP_OK, [
            'Access-Control-Allow-Origin' => '*',
        ]);
    }
}
