<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Every $revalidateAfter seconds, checks with the provider that the user may
 * still use the app: a page view goes through /oidc/connect?prompt=none, which
 * comes straight back (no screen) while the provider session is alive.
 *
 * That is what makes a change made at the provider reach an open session
 * within the delay: a role removed, an account disabled, a provider logout.
 * Only full-page GET navigations are redirected; form posts, XHR, JSON and
 * Turbo frames are left alone and the next page view does the check.
 */
final readonly class SessionRevalidationListener
{
    public function __construct(
        private SsoSession $ssoSession,
        private TokenStorageInterface $tokenStorage,
        private SsoUrlGenerator $urls,
        private ClockInterface $clock,
        private int $revalidateAfter,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        $request = $event->getRequest();
        if (!$event->isMainRequest() || $event->hasResponse() || !$this->isPageNavigation($request) || !$request->hasPreviousSession()) {
            return;
        }
        $route = $request->attributes->get('_route');
        if (SsoUrlGenerator::CONNECT_ROUTE === $route || SsoUrlGenerator::CALLBACK_ROUTE === $route) {
            return;
        }
        $authenticatedAt = $this->ssoSession->authenticatedAt($request->getSession());
        if (null === $authenticatedAt
            || $this->clock->now()->getTimestamp() - $authenticatedAt < $this->revalidateAfter
            || null === $this->tokenStorage->getToken()) {
            return;
        }

        $event->setResponse(new RedirectResponse($this->urls->connectPath([
            'prompt' => 'none',
            '_target_path' => $request->getRequestUri(),
        ])));
    }

    private function isPageNavigation(Request $request): bool
    {
        return $request->isMethod('GET')
            && !$request->isXmlHttpRequest()
            && !$request->headers->has('Turbo-Frame')
            && 'html' === $request->getPreferredFormat();
    }
}
