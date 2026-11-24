<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Security\Exception;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

/**
 * Why an SSO sign-in failed. The message is safe to show (and is the
 * translation key, domain "security"); the technical cause, for the logs, is the
 * previous exception. The reason is the code, which survives serialization.
 */
final class SsoAuthenticationException extends CustomUserMessageAuthenticationException
{
    /** Signed in at the provider, but no role for this app: an admin has to grant one. */
    public const int PENDING = 1;
    /** The user cancelled, or refused, at the provider. */
    public const int CANCELLED = 2;
    /** No sign-in in progress for this callback: expired, replayed or another browser. */
    public const int EXPIRED = 3;
    /** Background check (prompt=none): the provider session is over. */
    public const int SESSION_ENDED = 4;
    /** Anything else: provider error or unreachable, invalid token. */
    public const int FAILED = 5;
    /** The app refused the account, with its own message (SsoUserManagerInterface::provision()). */
    public const int REFUSED = 6;

    /** Errors of a prompt=none request meaning "the user has to sign in again". */
    private const array SESSION_ENDED_ERRORS = ['login_required', 'interaction_required', 'consent_required', 'account_selection_required'];

    public static function pending(): self
    {
        return new self('Your account does not have access to this application yet. An administrator has to grant it.', [], self::PENDING);
    }

    public static function cancelled(): self
    {
        return new self('Sign-in was cancelled.', [], self::CANCELLED);
    }

    public static function expired(): self
    {
        return new self('Your sign-in request has expired. Please try again.', [], self::EXPIRED);
    }

    public static function sessionEnded(): self
    {
        return new self('Your session has ended. Please sign in again.', [], self::SESSION_ENDED);
    }

    /**
     * The app's own refusal: its message (a translation key of the "security"
     * domain) is shown as is.
     *
     * @param array<mixed> $messageData
     */
    public static function refused(string $messageKey, array $messageData, \Throwable $previous): self
    {
        return new self($messageKey, $messageData, self::REFUSED, $previous);
    }

    public static function failed(string $cause, ?\Throwable $previous = null): self
    {
        return new self('Sign-in failed. Please try again.', [], self::FAILED, new OidcException($cause, 0, $previous));
    }

    /**
     * Maps the "error" a provider puts on the callback URL (RFC 6749 4.1.2.1,
     * OpenID Connect Core 3.1.2.6).
     */
    public static function fromProviderError(string $error, string $description, bool $silent): self
    {
        if ($silent && \in_array($error, self::SESSION_ENDED_ERRORS, true)) {
            return self::sessionEnded();
        }
        if ('access_denied' === $error) {
            return self::cancelled();
        }

        return self::failed(\sprintf('The identity provider returned "%s"%s.', $error, '' !== $description ? ': '.$description : ''));
    }

    public function getReason(): int
    {
        return (int) $this->getCode();
    }
}
