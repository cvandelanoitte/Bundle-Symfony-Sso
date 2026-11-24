<?php

declare(strict_types=1);

namespace Issl\SsoBundle\User;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The one piece each app writes: maps an SSO identity to its local user.
 *
 * The local user table stays: the business data points to it. It becomes a
 * profile linked to the provider account by the subject ("sub").
 */
interface SsoUserManagerInterface
{
    /**
     * Returns the local user of this identity, in this order:
     * 1. the user already linked to $identity->subject;
     * 2. else an existing, not yet linked user with the same verified email
     *    ({@see SsoIdentity::verifiedEmail()}): link it now;
     * 3. else a new user.
     * Then copies what the provider owns onto it (email, username, the roles of
     * $identity->roles) and saves it.
     *
     * Called on every sign-in, and on every API request authenticated by a token.
     *
     * @throws AuthenticationException to refuse the sign-in: the message of a
     *                                 CustomUserMessageAccountStatusException is shown to the user
     */
    public function provision(SsoIdentity $identity): UserInterface;
}
