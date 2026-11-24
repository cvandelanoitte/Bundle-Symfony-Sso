<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\TokenValidator;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Token handler of the API firewall:
 *
 *     access_token:
 *         token_handler: issl_sso.access_token_handler
 *
 * Validates the bearer token like the ID tokens of the browser sign-in (same
 * provider keys, refreshed after a key rotation), then hands its claims to the
 * firewall's user provider: issl_sso.user_provider.
 *
 * Rather than Symfony's "oidc" handler, which keeps the keys it downloaded for up
 * to an hour: a key rotation at the provider would refuse every API call that
 * long.
 */
final readonly class AccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private TokenValidator $tokenValidator,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        try {
            $claims = $this->tokenValidator->validateAccessToken($accessToken);
        } catch (OidcException $e) {
            $this->logger?->info('Access token refused: {reason}', ['reason' => $e->getMessage()]);

            throw new BadCredentialsException('Invalid credentials.', 0, $e);
        }

        $subject = $claims['sub'];
        if (!\is_string($subject) || '' === $subject) { // checked by the validator, restated for the types
            throw new BadCredentialsException('Invalid credentials.');
        }

        // No user loader: the firewall's user provider gets the claims.
        return new UserBadge($subject, null, $claims);
    }
}
