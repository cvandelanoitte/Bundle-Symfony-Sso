<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\OidcClient;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Logging out of the app also ends the provider session (RP-initiated logout):
 * otherwise the next visit would sign the user straight back in.
 *
 * Runs before Symfony's default logout redirect (priority 64) and before the
 * session is invalidated (priority 0): it needs the ID token stored in it. If
 * the provider cannot be reached, the logout stays local.
 */
final readonly class OidcLogoutListener
{
    public function __construct(
        private OidcClient $client,
        private SsoSession $ssoSession,
        private SsoUrlGenerator $urls,
        private string $postLogoutRedirectPath = '/',
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $request = $event->getRequest();
        if (null !== $event->getResponse() || !$request->hasSession()) {
            return;
        }
        $session = $request->getSession();
        if (!$this->ssoSession->isAuthenticated($session)) {
            return;
        }

        try {
            $url = $this->client->createEndSessionUrl(
                $this->ssoSession->idToken($session),
                $this->urls->absoluteUrl($request, $this->postLogoutRedirectPath),
            );
        } catch (OidcException $e) {
            $this->logger?->warning('The identity provider session could not be ended, the logout is local only.', ['exception' => $e]);

            return;
        }
        if (null !== $url) {
            $event->setResponse(new RedirectResponse($url));
        }
    }
}
