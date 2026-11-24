<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Unit\Security;

use Issl\SsoBundle\Oidc\AuthorizationRequest;
use Issl\SsoBundle\Security\PendingAuthorizationStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

final class PendingAuthorizationStoreTest extends TestCase
{
    public function testAStateCanBeUsedOnlyOnce(): void
    {
        $clock = new MockClock('@1000');
        $store = new PendingAuthorizationStore($clock);
        $session = new Session(new MockArraySessionStorage());
        $authorization = AuthorizationRequest::create(1000);

        $store->save($session, $authorization);

        self::assertEquals($authorization, $store->pull($session, $authorization->state));
        self::assertNull($store->pull($session, $authorization->state));
    }

    public function testExpiresAfterTenMinutes(): void
    {
        $clock = new MockClock('@1000');
        $store = new PendingAuthorizationStore($clock);
        $session = new Session(new MockArraySessionStorage());
        $authorization = AuthorizationRequest::create(1000);
        $store->save($session, $authorization);

        $clock->sleep(601);

        self::assertNull($store->pull($session, $authorization->state));
    }

    public function testKeepsTheLastFiveSignInsOnly(): void
    {
        $store = new PendingAuthorizationStore(new MockClock('@1000'));
        $session = new Session(new MockArraySessionStorage());
        $authorizations = [];
        for ($i = 0; $i < 6; ++$i) {
            $store->save($session, $authorizations[] = AuthorizationRequest::create(1000));
        }

        self::assertNull($store->pull($session, $authorizations[0]->state));
        self::assertNotNull($store->pull($session, $authorizations[1]->state));
        self::assertNotNull($store->pull($session, $authorizations[5]->state));
    }

    public function testUnknownStateIsRejected(): void
    {
        $store = new PendingAuthorizationStore(new MockClock('@1000'));

        self::assertNull($store->pull(new Session(new MockArraySessionStorage()), 'forged'));
    }
}
