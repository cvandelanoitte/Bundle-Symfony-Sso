<?php

declare(strict_types=1);

namespace Issl\SsoBundle;

use Issl\SsoBundle\Controller\OidcController;
use Issl\SsoBundle\Oidc\OidcClient;
use Issl\SsoBundle\Oidc\TokenValidator;
use Issl\SsoBundle\Security\AccessTokenHandler;
use Issl\SsoBundle\Security\FailureResponseFactory;
use Issl\SsoBundle\Security\OidcAuthenticator;
use Issl\SsoBundle\Security\OidcLogoutListener;
use Issl\SsoBundle\Security\PendingAuthorizationStore;
use Issl\SsoBundle\Security\SessionRevalidationListener;
use Issl\SsoBundle\Security\SsoSession;
use Issl\SsoBundle\Security\SsoUrlGenerator;
use Issl\SsoBundle\Security\SsoUserProvider;
use Issl\SsoBundle\User\RoleMapper;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\LogoutEvent;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/**
 * OpenID Connect single sign-on: see README.md for the setup.
 *
 * @phpstan-type SsoConfig array{
 *     issuer: string,
 *     discovery_uri: ?string,
 *     client_id: string,
 *     client_secret: string,
 *     app_url: ?string,
 *     user_manager: string,
 *     user_class: class-string,
 *     scopes: list<string>,
 *     roles: array{claim: string, map: array<string, string>, require_any: bool},
 *     login: array{default_target_path: string, failure_path: ?string, post_logout_redirect_path: string, revalidate_after: int},
 *     cache: string,
 *     http_client: string,
 *     leeway: int,
 * }
 */
final class IsslSsoBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('issuer')
                    ->info('Public issuer URL, the "iss" of the tokens, e.g. https://auth.example.com/realms/issl')
                    ->isRequired()->cannotBeEmpty()
                ->end()
                ->scalarNode('discovery_uri')
                    ->info('Base URL this server uses to reach the provider, when it differs from the issuer (internal Docker URL, e.g. http://keycloak:8080/realms/issl). Defaults to the issuer.')
                    ->defaultNull()
                ->end()
                ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('client_secret')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('app_url')
                    ->info('Public URL of this app (https://cooking.example.com): base of the redirect URIs sent to the provider. Defaults to the URL of the request, which a TLS-terminating proxy can turn into http://.')
                    ->defaultNull()
                ->end()
                ->scalarNode('user_manager')
                    ->info('Service id of the app\'s Issl\SsoBundle\User\SsoUserManagerInterface.')
                    ->isRequired()->cannotBeEmpty()
                ->end()
                ->scalarNode('user_class')
                    ->info('Class of the app\'s users (for the API user provider).')
                    ->isRequired()->cannotBeEmpty()
                ->end()
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email'])
                ->end()
                ->arrayNode('roles')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('claim')
                            ->info('Dot-separated path of the provider roles of this app in the token; "{client_id}" is replaced by the client id.')
                            ->defaultValue('resource_access.{client_id}.roles')
                        ->end()
                        ->arrayNode('map')
                            ->info('Provider role => Symfony role. Provider roles left out are ignored.')
                            ->useAttributeAsKey('name')
                            ->normalizeKeys(false)
                            ->scalarPrototype()->end()
                            ->defaultValue(['user' => 'ROLE_USER', 'admin' => 'ROLE_SUPER_ADMIN'])
                        ->end()
                        ->booleanNode('require_any')
                            ->info('Refuse the sign-in ("access pending") when the account has no mapped role for this app.')
                            ->defaultTrue()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('login')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('default_target_path')->defaultValue('/')->end()
                        ->scalarNode('failure_path')
                            ->info('Route or path to redirect to when a sign-in fails, with ?reason= and an "issl_sso_error" flash. Null renders a built-in page.')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('post_logout_redirect_path')
                            ->info('Route or path the provider sends the user back to after a logout. Must be registered for the client.')
                            ->defaultValue('/')
                        ->end()
                        ->integerNode('revalidate_after')
                            ->info('Seconds after which a page view silently re-checks the account with the provider (roles, disabled account, provider logout). 0 disables it.')
                            ->defaultValue(3600)
                            ->min(0)
                        ->end()
                    ->end()
                ->end()
                ->scalarNode('cache')->info('Cache pool for the discovery document and the signing keys.')->defaultValue('cache.app')->end()
                ->scalarNode('http_client')->defaultValue('http_client')->end()
                ->integerNode('leeway')->info('Clock skew tolerated on the ID token dates, in seconds.')->defaultValue(30)->min(0)->end()
            ->end();
    }

    /**
     * @param array<mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        /** @var SsoConfig $config */
        $services = $container->services();

        $services->set('issl_sso.oidc_client', OidcClient::class)
            ->args([
                service($config['http_client']),
                service($config['cache']),
                service('clock'),
                $config['issuer'],
                $config['discovery_uri'] ?? $config['issuer'],
                $config['client_id'],
                $config['client_secret'],
            ]);
        $services->alias(OidcClient::class, 'issl_sso.oidc_client');

        $services->set('issl_sso.token_validator', TokenValidator::class)
            ->args([service('issl_sso.oidc_client'), service('clock'), $config['leeway']]);

        $services->set('issl_sso.role_mapper', RoleMapper::class)
            ->args([$config['roles']['claim'], $config['client_id'], $config['roles']['map']]);
        $services->alias(RoleMapper::class, 'issl_sso.role_mapper');

        $services->set('issl_sso.session', SsoSession::class)->args([service('clock')]);
        $services->set('issl_sso.pending_authorizations', PendingAuthorizationStore::class)->args([service('clock')]);
        $services->set('issl_sso.url_generator', SsoUrlGenerator::class)
            ->args([service('router'), service('security.http_utils'), $config['app_url']]);
        $services->set('issl_sso.failure_responses', FailureResponseFactory::class)
            ->args([
                service('security.http_utils'),
                service('issl_sso.url_generator'),
                $config['login']['failure_path'],
                service('translator')->nullOnInvalid(),
            ]);

        // Public id = class name, as security.yaml refers to it:
        // custom_authenticators: [Issl\SsoBundle\Security\OidcAuthenticator]
        $services->set(OidcAuthenticator::class)
            ->args([
                service('issl_sso.oidc_client'),
                service('issl_sso.token_validator'),
                service('issl_sso.role_mapper'),
                service('issl_sso.pending_authorizations'),
                service($config['user_manager']),
                service('issl_sso.session'),
                service('issl_sso.url_generator'),
                service('issl_sso.failure_responses'),
                service('security.http_utils'),
                service('security.token_storage'),
                $config['roles']['require_any'],
                $config['login']['default_target_path'],
                service('logger')->nullOnInvalid(),
            ])
            ->tag('monolog.logger', ['channel' => 'security']);

        // The API firewall: access_token: { token_handler: issl_sso.access_token_handler }
        // with providers: { sso: { id: issl_sso.user_provider } }.
        $services->set('issl_sso.access_token_handler', AccessTokenHandler::class)
            ->args([service('issl_sso.token_validator'), service('logger')->nullOnInvalid()])
            ->tag('monolog.logger', ['channel' => 'security']);
        $services->alias(AccessTokenHandler::class, 'issl_sso.access_token_handler');

        $services->set('issl_sso.user_provider', SsoUserProvider::class)
            ->args([
                service($config['user_manager']),
                service('issl_sso.role_mapper'),
                $config['user_class'],
                $config['roles']['require_any'],
            ]);

        $services->set(OidcController::class)
            ->args([
                service('issl_sso.oidc_client'),
                service('issl_sso.pending_authorizations'),
                service('issl_sso.url_generator'),
                service('clock'),
                $config['scopes'],
                service('logger')->nullOnInvalid(),
            ])
            ->tag('controller.service_arguments')
            ->tag('monolog.logger', ['channel' => 'security']);

        // A global listener: the security bundle copies it to every firewall.
        $services->set('issl_sso.logout_listener', OidcLogoutListener::class)
            ->args([
                service('issl_sso.oidc_client'),
                service('issl_sso.session'),
                service('issl_sso.url_generator'),
                $config['login']['post_logout_redirect_path'],
                service('logger')->nullOnInvalid(),
            ])
            ->tag('kernel.event_listener', ['event' => LogoutEvent::class, 'priority' => 128])
            ->tag('monolog.logger', ['channel' => 'security']);

        if ($config['login']['revalidate_after'] > 0) {
            // After the firewall (priority 8), which loads the token.
            $services->set('issl_sso.session_revalidation_listener', SessionRevalidationListener::class)
                ->args([
                    service('issl_sso.session'),
                    service('security.token_storage'),
                    service('issl_sso.url_generator'),
                    service('clock'),
                    $config['login']['revalidate_after'],
                ])
                ->tag('kernel.event_listener', ['event' => KernelEvents::REQUEST, 'priority' => 0]);
        }
    }
}
