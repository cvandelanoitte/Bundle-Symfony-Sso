<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security;

use Issl\SsoBundle\Security\Exception\SsoAuthenticationException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The response to a failed sign-in.
 *
 * With a failure path (a route or a path of the app), redirects there with
 * "?reason=pending|cancelled|expired|failed" and the message as a flash
 * ("issl_sso_error"): the app renders its own page. Without one, renders a
 * minimal page, so that an API-first app needs no template.
 */
final readonly class FailureResponseFactory
{
    private const array REASONS = [
        SsoAuthenticationException::PENDING => 'pending',
        SsoAuthenticationException::CANCELLED => 'cancelled',
        SsoAuthenticationException::EXPIRED => 'expired',
        SsoAuthenticationException::SESSION_ENDED => 'session_ended',
        SsoAuthenticationException::FAILED => 'failed',
        SsoAuthenticationException::REFUSED => 'refused',
    ];

    public function __construct(
        private HttpUtils $httpUtils,
        private SsoUrlGenerator $urls,
        private ?string $failurePath = null,
        private ?TranslatorInterface $translator = null,
    ) {
    }

    public function create(Request $request, SsoAuthenticationException $exception): Response
    {
        $reason = self::REASONS[$exception->getReason()] ?? 'failed';
        /** @var array<string, mixed> $parameters */
        $parameters = $exception->getMessageData();
        $message = $this->translate($exception->getMessageKey(), $parameters);

        if (null !== $this->failurePath) {
            $session = $request->hasSession() ? $request->getSession() : null;
            if ($session instanceof FlashBagAwareSessionInterface) {
                $session->getFlashBag()->add('issl_sso_error', $message);
            }
            $url = $this->httpUtils->generateUri($request, $this->failurePath);

            return $this->httpUtils->createRedirectResponse($request, $url.(str_contains($url, '?') ? '&' : '?').'reason='.$reason);
        }

        return $this->page($request, $exception, $message);
    }

    private function page(Request $request, SsoAuthenticationException $exception, string $message): Response
    {
        $pending = SsoAuthenticationException::PENDING === $exception->getReason();
        // Pending: the provider account is fine, offer to switch to another one.
        $retryUrl = $pending
            ? $this->urls->connectPath(['prompt' => 'login'])
            : $this->urls->connectPath();
        $retryLabel = $this->translate($pending ? 'Sign in with another account' : 'Try again');
        $title = $this->translate(match ($exception->getReason()) {
            SsoAuthenticationException::PENDING => 'Access pending',
            SsoAuthenticationException::REFUSED => 'Access refused',
            default => 'Sign-in failed',
        });

        $html = \sprintf(
            '<!doctype html><html lang="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>%s</title></head>'
            .'<body style="font-family:system-ui,sans-serif;max-width:34rem;margin:15vh auto;padding:0 1rem;line-height:1.5">'
            .'<h1 style="font-size:1.4rem">%2$s</h1><p>%s</p><p><a href="%s">%s</a></p></body></html>',
            self::escape($request->getLocale()),
            self::escape($title),
            self::escape($message),
            self::escape($retryUrl),
            self::escape($retryLabel),
        );

        return new Response($html, $pending ? Response::HTTP_FORBIDDEN : Response::HTTP_UNAUTHORIZED, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store',
        ]);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function translate(string $message, array $parameters = []): string
    {
        return null !== $this->translator ? $this->translator->trans($message, $parameters, 'security') : strtr($message, array_map(static fn (mixed $value): string => \is_scalar($value) ? (string) $value : '', $parameters));
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
