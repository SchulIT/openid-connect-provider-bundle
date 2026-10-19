<?php

declare(strict_types=1);

namespace Ajgarlag\Bundle\OpenIDConnectProviderBundle\OpenIDConnect;

use Ajgarlag\Bundle\OpenIDConnectProviderBundle\Event\UserClaimsResolveEvent;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\Bundle\OAuth2ServerBundle\Security\Authentication\Token\OAuth2Token;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

readonly class UserInfoResponse
{
    public function __construct(
        private ClaimExtractor $claimExtractor,
        private IdentityProviderInterface $identityProvider,
        private EventDispatcherInterface $eventDispatcher,
        private RequestStack $requestStack,
    ) {
    }

    public function resolveClaims(OAuth2Token $accessToken): array
    {
        $event = new UserClaimsResolveEvent($accessToken->getUserIdentifier());
        $this->eventDispatcher->dispatch($event);

        $claims = $event->getClaims();
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $claims);

        // Add default claims
        $defaultClaims = [
            RegisteredClaims::ISSUER => $this->getIssuer(),
            RegisteredClaims::SUBJECT => $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier())->getIdentifier(),
            RegisteredClaims::AUDIENCE => $accessToken->getOAuthClientId(),
        ];

        return array_merge($defaultClaims, $claims);
    }

    private function getIssuer(): ?string
    {
        if (null === $this->requestStack->getMainRequest()) {
            return null;
        }

        return $this->requestStack->getMainRequest()->getSchemeAndHttpHost() . $this->requestStack->getMainRequest()->getBasePath();
    }
}
