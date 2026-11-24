<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc\Exception;

/**
 * A failure while talking to the identity provider or validating what it returned.
 *
 * The message is meant for the logs: it can name the claim or the endpoint at
 * fault, so it is never shown to the user as is.
 */
final class OidcException extends \RuntimeException
{
}
