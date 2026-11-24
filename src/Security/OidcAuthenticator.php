<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Issl\SsoBundle\Oidc\OidcClient;
use Issl\SsoBundle\Oidc\TokenValidator;
use Issl\SsoBundle\Security\Exception\SsoAuthenticationException;
use Issl\SsoBundle\User\RoleMapper;
use Issl\SsoBundle\User\SsoIdentity;
use Issl\SsoBundle\User\SsoUserManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAccountStatusException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Browser sign-in, Authorization Code flow with PKCE.
 *
 * - As the entry point, sends anonymous visitors to /oidc/connect, which
 *   redirects to the provider (see OidcController).
 * - Handles /oidc/callback: checks the state, exchanges the code, validates the
 *   ID token, maps the roles, and hands the identity to the app's
 *   SsoUserManagerInterface. Then the app has its own session, as with a form
 *   login.
 *
 * Holds no per-request state (safe under long-running workers): what a request
 * needs between authenticate() and onAuthenticationSuccess() travels in the
 * request attributes.
 */
final class OidcAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    private const string ATTRIBUTE_ID_TOKEN = '_issl_sso_id_token';
    private const string ATTRIBUTE_TARGET_PATH = '_issl_sso_target_path';
    /** Request attribute of the callback of a silent check: see isSilentCheck(). */
    public const string SILENT_CHECK_ATTRIBUTE = '_issl_sso_silent';

    public function __construct(
        private readonly OidcClient $client,
        private readonly TokenValidator $tokenValidator,
        private readonly RoleMapper $roleMapper,
        private readonly PendingAuthorizationStore $pendingAuthorizations,
        private readonly SsoUserManagerInterface $userManager,
        private readonly SsoSession $ssoSession,
        private readonly SsoUrlGenerator $urls,
        private readonly FailureResponseFactory $failureResponses,
        private readonly HttpUtils $httpUtils,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly bool $requireRole = true,
        private readonly string $defaultTargetPath = '/',
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /**
     * True when this request is the callback of a silent check (the periodic
     * prompt=none of an open session), not a sign-in: it raises a
     * LoginSuccessEvent as well, which an app counting sign-ins skips.
     */
    public static function isSilentCheck(Request $request): bool
    {
        return true === $request->attributes->get(self::SILENT_CHECK_ATTRIBUTE);
    }

    public function supports(Request $request): bool
    {
        return $this->httpUtils->checkRequestPath($request, SsoUrlGenerator::CALLBACK_ROUTE);
    }

    public function authenticate(Request $request): Passport
    {
        $state = $request->query->getString('state');
        $authorization = '' !== $state ? $this->pendingAuthorizations->pull($request->getSession(), $state) : null;
        $request->attributes->set(self::ATTRIBUTE_TARGET_PATH, $authorization?->targetPath);
        $request->attributes->set(self::SILENT_CHECK_ATTRIBUTE, $authorization->silent ?? false);

        $error = $request->query->getString('error');
        if ('' !== $error) {
            throw SsoAuthenticationException::fromProviderError($error, $request->query->getString('error_description'), $authorization->silent ?? false);
        }
        if (null === $authorization) {
            throw SsoAuthenticationException::expired();
        }
        $code = $request->query->getString('code');
        if ('' === $code) {
            throw SsoAuthenticationException::failed('The callback has no authorization code.');
        }

        try {
            $tokens = $this->client->exchangeAuthorizationCode($code, $authorization->codeVerifier, $this->urls->callbackUrl($request));
            $claims = $this->tokenValidator->validateIdToken($tokens->idToken, $authorization->nonce);
        } catch (OidcException $e) {
            throw SsoAuthenticationException::failed($e->getMessage(), $e);
        }

        $identity = SsoIdentity::fromClaims($claims, $this->roleMapper);
        if ($this->requireRole && [] === $identity->roles) {
            $this->logger?->info('SSO sign-in refused: the account has no role for this application.', ['subject' => $identity->subject]);

            throw SsoAuthenticationException::pending();
        }
        $request->attributes->set(self::ATTRIBUTE_ID_TOKEN, $tokens->idToken);

        return new SelfValidatingPassport(new UserBadge(
            $identity->subject,
            fn (): UserInterface => $this->userManager->provision($identity),
        ));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        $session = $request->getSession();
        $idToken = $request->attributes->get(self::ATTRIBUTE_ID_TOKEN);
        $this->ssoSession->markAuthenticated($session, \is_string($idToken) ? $idToken : null);

        $targetPath = $request->attributes->get(self::ATTRIBUTE_TARGET_PATH);
        if (!\is_string($targetPath) || '' === $targetPath) {
            $targetPath = $this->getTargetPath($session, $firewallName);
        }
        $this->removeTargetPath($session, $firewallName);

        return $this->httpUtils->createRedirectResponse($request, $targetPath ?? $this->defaultTargetPath);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $exception = match (true) {
            $exception instanceof SsoAuthenticationException => $exception,
            // Thrown by the app's SsoUserManager to refuse someone: its message is for the user.
            $exception instanceof CustomUserMessageAccountStatusException,
            $exception instanceof CustomUserMessageAuthenticationException => SsoAuthenticationException::refused($exception->getMessageKey(), $exception->getMessageData(), $exception),
            default => SsoAuthenticationException::failed($exception->getMessage(), $exception),
        };
        $this->logger?->notice('SSO sign-in failed: {reason}', [
            'reason' => $exception->getPrevious()?->getMessage() ?? $exception->getMessageKey(),
            'exception' => $exception,
        ]);

        // The periodic silent check failed, or the account lost its access to the
        // app: the local session must not outlive it.
        $session = $request->getSession();
        $accessLost = true === $request->attributes->get(self::SILENT_CHECK_ATTRIBUTE)
            || \in_array($exception->getReason(), [SsoAuthenticationException::SESSION_ENDED, SsoAuthenticationException::PENDING], true);
        if ($accessLost && $this->ssoSession->isAuthenticated($session)) {
            // Both: the firewall would otherwise save the token still in memory
            // into the new session at the end of the request.
            $this->tokenStorage->setToken(null);
            $session->invalidate();
        }
        if (SsoAuthenticationException::SESSION_ENDED === $exception->getReason()) {
            $targetPath = $request->attributes->get(self::ATTRIBUTE_TARGET_PATH);

            return new RedirectResponse($this->urls->connectPath(['_target_path' => \is_string($targetPath) ? $targetPath : null]));
        }

        return $this->failureResponses->create($request, $exception);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // A script or an XHR cannot follow a redirect to a login page.
        if ($request->isXmlHttpRequest() || 'json' === $request->getPreferredFormat()) {
            return new JsonResponse(['error' => 'authentication_required'], Response::HTTP_UNAUTHORIZED);
        }

        // The firewall already saved the requested URL as the target path.
        return new RedirectResponse($this->urls->connectPath());
    }
}
