issl/sso-bundle
===============

OpenID Connect single sign-on for the ISSL Symfony apps:

- **browser sign-in**: Authorization Code flow with PKCE, `state` and `nonce`, ID
  token validation (signature with the provider keys, issuer, audience, authorized
  party, dates, nonce), then a normal Symfony session;
- **rights per app**: the provider roles of this app (Keycloak client roles by
  default) mapped to Symfony roles; an account without any gets "access pending";
- **logout** of the app and of the provider (RP-initiated logout);
- **silent re-check** of open sessions (`prompt=none`), so that a role removed or an
  account disabled reaches them within the hour;
- **APIs**: a token handler and a user provider for Symfony's `access_token`
  authenticator, for bearer tokens of the provider (keys refreshed after a key
  rotation, unlike Symfony's own `oidc` handler, which keeps them up to an hour);
- **local users**: one interface to implement, mapping the provider account to the
  app's user.

Symfony 7.4 and 8.x, PHP 8.4+, php-fpm or RoadRunner (no per-request state in the
services). Provider-agnostic OIDC; set up and documented for Keycloak in the
**App-Sso-Keycloak** repository:
[doc/SSO.md](https://github.com/cvandelanoitte/App-Sso-Keycloak/blob/main/doc/SSO.md)
explains the mechanism,
[doc/INTEGRATION.md](https://github.com/cvandelanoitte/App-Sso-Keycloak/blob/main/doc/INTEGRATION.md)
wires an app step by step.

# Install

```bash
composer config repositories.sso-bundle vcs https://github.com/cvandelanoitte/Bundle-Symfony-Sso.git
composer require issl/sso-bundle:^0.1
```

Flex registers the bundle. Then:

```yaml
# config/packages/issl_sso.yaml
issl_sso:
    issuer: '%env(OIDC_ISSUER)%'                  # https://auth.example.com/realms/issl
    discovery_uri: '%env(OIDC_DISCOVERY_URI)%'    # internal URL, defaults to the issuer
    client_id: '%env(OIDC_CLIENT_ID)%'
    client_secret: '%env(OIDC_CLIENT_SECRET)%'
    app_url: '%env(default::OIDC_APP_URL)%'
    user_manager: App\Security\SsoUserManager     # implements SsoUserManagerInterface
    user_class: App\Entity\User

# config/routes/issl_sso.yaml
issl_sso:
    resource: '@IsslSsoBundle/config/routes.php'  # /oidc/connect, /oidc/callback
```

```yaml
# config/packages/security.yaml (session firewall)
main:
    provider: users                               # the app's entity provider
    custom_authenticators: [Issl\SsoBundle\Security\OidcAuthenticator]
    entry_point: Issl\SsoBundle\Security\OidcAuthenticator
    logout: { path: /logout }
```

The API firewall, the options and the user manager:
[INTEGRATION.md](https://github.com/cvandelanoitte/App-Sso-Keycloak/blob/main/doc/INTEGRATION.md).

# The contract

```php
interface SsoUserManagerInterface
{
    /** The local user of this identity: found by subject, else linked, else created; profile and roles copied. */
    public function provision(SsoIdentity $identity): UserInterface;
}
```

`SsoIdentity` carries `subject`, `email`, `emailVerified`, `username`, `name`,
`roles` (mapped for this app) and every `claims`; `verifiedEmail()` is the email to
link existing accounts with. To refuse someone, throw a
`CustomUserMessageAccountStatusException`: its message is shown to the user.

The silent checks of open sessions raise `LoginSuccessEvent` like the sign-ins:
`OidcAuthenticator::isSilentCheck($request)` tells them apart (for analytics).

# Design

| Class | Role |
|---|---|
| `Oidc\OidcClient` | discovery (cached), signing keys (cached, refreshed on an unknown key at most once a minute), authorization URL, code exchange (`client_secret_post`), end-session URL |
| `Oidc\TokenValidator` | ID tokens (OpenID Connect Core 3.1.3.7) and access tokens: signature with the provider keys, issuer, audience, dates, with web-token |
| `Security\AccessTokenHandler` | API firewall: the bearer token, validated like the ID tokens (keys refreshed after a rotation) |
| `Oidc\AuthorizationRequest` | state, nonce, PKCE verifier of a sign-in in progress |
| `Security\OidcAuthenticator` | the callback, the entry point, success and failure |
| `Security\PendingAuthorizationStore` | sign-ins in progress in the session: 5 at most, 10 minutes, single use |
| `Security\OidcLogoutListener` | redirects the logout to the provider's end-session endpoint |
| `Security\SessionRevalidationListener` | the hourly `prompt=none` check of open sessions |
| `Security\SsoUserProvider` | API firewall: claims of a validated token -> local user |
| `Security\FailureResponseFactory` | the failure page, or a redirect to the app's own |
| `User\RoleMapper` | provider roles of this app -> Symfony roles |
| `Controller\OidcController` | `/oidc/connect` |

# Development

The tests and the QA tools run in Docker (PHP 8.5), the tools isolated in `tools/`:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app composer:2 composer install
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app/tools composer:2 composer install
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app composer:2 php vendor/bin/phpunit
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app composer:2 php -d memory_limit=1G tools/vendor/bin/phpstan analyse
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/app -w /app composer:2 php tools/vendor/bin/php-cs-fixer fix --dry-run --diff
```

`tests/Functional/SsoFlowTest.php` runs the whole browser and API flows against a
fake provider (`tests/Support/TestIdentityProvider.php`, tokens signed with a key
generated per run). Tested with Symfony 8.1 and 7.4, web-token 4.2.
