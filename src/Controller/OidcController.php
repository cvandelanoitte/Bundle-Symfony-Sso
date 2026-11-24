<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Controller;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\OidcClient;
use Issl\SsoBundle\Security\PendingAuthorizationStore;
use Issl\SsoBundle\Security\SsoUrlGenerator;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;

/**
 * GET /oidc/connect: starts a sign-in and redirects to the provider.
 *
 * Query parameters, both optional:
 * - _target_path: where to go once signed in (a path of this app);
 * - prompt:       "login" (ask for the password even with a provider session,
 *                 e.g. to switch account), "create" (open the sign-up page),
 *                 "none" (background check, used by the revalidation).
 */
final readonly class OidcController
{
    private const array PROMPTS = ['none', 'login', 'create'];

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        private OidcClient $client,
        private PendingAuthorizationStore $pendingAuthorizations,
        private SsoUrlGenerator $urls,
        private ClockInterface $clock,
        private array $scopes,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function connect(Request $request): RedirectResponse
    {
        $targetPath = $request->query->getString('_target_path');
        $prompt = $request->query->getString('prompt');
        $prompt = \in_array($prompt, self::PROMPTS, true) ? $prompt : null;

        $authorization = AuthorizationRequest::create(
            $this->clock->now()->getTimestamp(),
            self::isLocalPath($targetPath) ? $targetPath : null,
            'none' === $prompt,
        );
        $this->pendingAuthorizations->save($request->getSession(), $authorization);

        try {
            $url = $this->client->createAuthorizationUrl($authorization, $this->urls->callbackUrl($request), $this->scopes, $prompt);
        } catch (OidcException $e) {
            $this->logger?->error('The sign-in could not start: {reason}', ['reason' => $e->getMessage(), 'exception' => $e]);

            throw new ServiceUnavailableHttpException(60, 'The sign-in service is unavailable, please try again later.', $e);
        }

        return new RedirectResponse($url);
    }

    /**
     * Never reached when the firewall is configured: the OidcAuthenticator
     * answers this path first.
     */
    public function callback(): never
    {
        throw new \LogicException('The OIDC callback was not handled: add "Issl\SsoBundle\Security\OidcAuthenticator" to the "custom_authenticators" of the firewall that covers /oidc/callback.');
    }

    /**
     * Only a path of this app: "/x" but neither "//host" nor "/\host", which
     * browsers read as another host (open redirect).
     */
    private static function isLocalPath(string $path): bool
    {
        return str_starts_with($path, '/') && !str_starts_with($path, '//') && !str_contains($path, '\\');
    }
}
