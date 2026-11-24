<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\HttpUtils;

/**
 * Builds the URLs given to the identity provider: they must match the ones
 * registered for the client, character for character.
 *
 * Behind a proxy that terminates TLS, the request may look like
 * "http://app:80"; set $appUrl ("https://cooking.example.com") and every
 * absolute URL is built from it instead of from the request.
 */
final readonly class SsoUrlGenerator
{
    public const string CONNECT_ROUTE = 'issl_sso_connect';
    public const string CALLBACK_ROUTE = 'issl_sso_callback';

    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
        private HttpUtils $httpUtils,
        private ?string $appUrl = null,
    ) {
    }

    public function callbackUrl(Request $request): string
    {
        return $this->absoluteUrl($request, self::CALLBACK_ROUTE);
    }

    /**
     * @param string $pathOrRoute an absolute path ("/"), a route name or an absolute URL
     */
    public function absoluteUrl(Request $request, string $pathOrRoute): string
    {
        if (null === $this->appUrl || str_contains($pathOrRoute, '://')) {
            return $this->httpUtils->generateUri($request, $pathOrRoute);
        }
        $path = str_starts_with($pathOrRoute, '/') ? $pathOrRoute : $this->urlGenerator->generate($pathOrRoute);

        return rtrim($this->appUrl, '/').$path;
    }

    /**
     * The path that starts a sign-in.
     *
     * @param array<string, string|null> $query "_target_path" and "prompt"
     */
    public function connectPath(array $query = []): string
    {
        return $this->urlGenerator->generate(self::CONNECT_ROUTE, array_filter($query, static fn (?string $value): bool => null !== $value && '' !== $value));
    }
}
