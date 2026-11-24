<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Support;

use Issl\SsoBundle\Security\OidcAuthenticator;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Records the sign-ins as an app counting them would see them.
 */
final class TestLoginRecorder
{
    /** @var list<bool> one entry per LoginSuccessEvent of the bundle: true for a silent check */
    public array $silentChecks = [];

    public function __invoke(LoginSuccessEvent $event): void
    {
        if ($event->getAuthenticator() instanceof OidcAuthenticator) {
            $this->silentChecks[] = OidcAuthenticator::isSilentCheck($event->getRequest());
        }
    }
}
