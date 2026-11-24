<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc;

use Issl\SsoBundle\Oidc\Exception\OidcException;

/**
 * What the token endpoint returns for an authorization code.
 */
final readonly class TokenResponse
{
    public function __construct(
        public string $idToken,
        public string $accessToken,
        public ?string $refreshToken = null,
        public ?int $expiresIn = null,
    ) {
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $idToken = $data['id_token'] ?? null;
        $accessToken = $data['access_token'] ?? null;
        if (!\is_string($idToken) || '' === $idToken) {
            throw new OidcException('The token response has no "id_token": is the "openid" scope requested?');
        }
        if (!\is_string($accessToken) || '' === $accessToken) {
            throw new OidcException('The token response has no "access_token".');
        }
        $refreshToken = $data['refresh_token'] ?? null;
        $expiresIn = $data['expires_in'] ?? null;

        return new self(
            $idToken,
            $accessToken,
            \is_string($refreshToken) && '' !== $refreshToken ? $refreshToken : null,
            \is_int($expiresIn) ? $expiresIn : null,
        );
    }
}
