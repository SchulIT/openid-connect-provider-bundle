<?php

declare(strict_types=1);

namespace Ajgarlag\Bundle\OpenIDConnectProviderBundle\Controller;

use Ajgarlag\Bundle\OpenIDConnectProviderBundle\Event\UserClaimsResolveEvent;
use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use OpenIDConnectServer\ClaimExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final readonly class UserInfoController
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private ClaimExtractor $claimExtractor,
        private EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->tokenStorage->getToken();

        if (!$token instanceof OAuth2Token) {
            throw new UnauthorizedHttpException('oauth2', 'No OAuth2/OIDC token found.');
        }

        $event = new UserClaimsResolveEvent($token->getUserIdentifier());
        $this->eventDispatcher->dispatch($event);

        $claims = $event->getClaims();
        $extractedClaims = $this->claimExtractor->extract($token->getScopes(), $claims);

        return new JsonResponse($extractedClaims, Response::HTTP_OK, [
            'Access-Control-Allow-Origin' => '*',
        ]);
    }
}
