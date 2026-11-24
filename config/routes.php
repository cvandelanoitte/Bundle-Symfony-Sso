<?php

declare(strict_types=1);

use Issl\SsoBundle\Controller\OidcController;
use Issl\SsoBundle\Security\SsoUrlGenerator;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * Import in the app (config/routes/issl_sso.yaml):
 *
 *     issl_sso:
 *         resource: '@IsslSsoBundle/config/routes.php'
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add(SsoUrlGenerator::CONNECT_ROUTE, '/oidc/connect')
        ->controller([OidcController::class, 'connect'])
        ->methods(['GET']);

    $routes->add(SsoUrlGenerator::CALLBACK_ROUTE, '/oidc/callback')
        ->controller([OidcController::class, 'callback'])
        ->methods(['GET']);
};
