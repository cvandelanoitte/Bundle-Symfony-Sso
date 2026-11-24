<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Tests\Support;

use Issl\SsoBundle\IsslSsoBundle;
use Issl\SsoBundle\Security\OidcAuthenticator;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * A minimal app: a session firewall signed in through the bundle, and a
 * bearer-token API firewall validated by Symfony's "oidc" token handler.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new IsslSsoBundle();
    }

    public function getProjectDir(): string
    {
        // Not the bundle folder: Symfony writes config/reference.php into the project.
        return sys_get_temp_dir().'/issl-sso-bundle-tests';
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/issl-sso-bundle-tests/'.$this->environment.'/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/issl-sso-bundle-tests/'.$this->environment.'/log';
    }

    public function home(#[CurrentUser] UserInterface $user): Response
    {
        return new Response('Hello '.$user->getUserIdentifier().' '.implode(',', $user->getRoles()));
    }

    public function admin(): Response
    {
        return new Response('Admin area');
    }

    public function apiMe(#[CurrentUser] TestUser $user): JsonResponse
    {
        return new JsonResponse(['subject' => $user->ssoSubject, 'email' => $user->email, 'roles' => $user->getRoles()]);
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            'router' => ['utf8' => true],
            'http_client' => ['mock_response_factory' => 'test.identity_provider'],
            'cache' => ['app' => 'cache.adapter.array'],
            'php_errors' => ['log' => true],
        ]);
        $container->extension('security', [
            'providers' => [
                'local' => ['id' => TestUserManager::class],
                'sso' => ['id' => 'issl_sso.user_provider'],
            ],
            'firewalls' => [
                'api' => [
                    'pattern' => '^/api/',
                    'stateless' => true,
                    'provider' => 'sso',
                    'access_token' => ['token_handler' => 'issl_sso.access_token_handler'],
                ],
                'main' => [
                    'lazy' => true,
                    'provider' => 'local',
                    'custom_authenticators' => [OidcAuthenticator::class],
                    'entry_point' => OidcAuthenticator::class,
                    'logout' => ['path' => 'logout'],
                ],
            ],
            'access_control' => [
                ['path' => '^/oidc/', 'roles' => 'PUBLIC_ACCESS'],
                ['path' => '^/admin', 'roles' => 'ROLE_SUPER_ADMIN'],
                ['path' => '^/', 'roles' => 'ROLE_USER'],
            ],
        ]);
        $container->extension('issl_sso', [
            'issuer' => TestIdentityProvider::ISSUER,
            'discovery_uri' => TestIdentityProvider::INTERNAL_URI,
            'client_id' => TestIdentityProvider::CLIENT_ID,
            'client_secret' => TestIdentityProvider::CLIENT_SECRET,
            'app_url' => 'https://cooking.test',
            'user_manager' => TestUserManager::class,
            'user_class' => TestUser::class,
        ]);

        $services = $container->services();
        // The expected failures would otherwise be logged to stderr.
        $services->set('logger', NullLogger::class);
        $services->set('test.identity_provider', TestIdentityProvider::class)->public();
        $services->set(TestUserManager::class)->public();
        $services->set(TestLoginRecorder::class)->public()
            ->tag('kernel.event_listener', ['event' => LoginSuccessEvent::class]);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import(\dirname(__DIR__, 2).'/config/routes.php');
        $routes->add('home', '/')->controller([self::class, 'home']);
        $routes->add('admin', '/admin')->controller([self::class, 'admin']);
        $routes->add('api_me', '/api/me')->controller([self::class, 'apiMe']);
        $routes->add('logout', '/logout')->methods(['GET']);
    }
}
