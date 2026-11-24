<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc;

use Issl\SsoBundle\Oidc\Exception\OidcException;

/**
 * The endpoints of the identity provider, read from its discovery document
 * (/.well-known/openid-configuration).
 */
final readonly class ProviderMetadata
{
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $endSessionEndpoint = null,
    ) {
    }

    /**
     * @param array<mixed> $document
     */
    public static function fromDiscoveryDocument(array $document): self
    {
        return new self(
            self::requireString($document, 'issuer'),
            self::requireString($document, 'authorization_endpoint'),
            self::requireString($document, 'token_endpoint'),
            self::requireString($document, 'jwks_uri'),
            self::optionalString($document, 'end_session_endpoint'),
        );
    }

    /**
     * @param array<mixed> $document
     */
    private static function requireString(array $document, string $key): string
    {
        return self::optionalString($document, $key)
            ?? throw new OidcException(\sprintf('The discovery document has no "%s".', $key));
    }

    /**
     * @param array<mixed> $document
     */
    private static function optionalString(array $document, string $key): ?string
    {
        $value = $document[$key] ?? null;

        return \is_string($value) && '' !== $value ? $value : null;
    }
}
