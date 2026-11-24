<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc;

use Issl\SsoBundle\Oidc\Exception\OidcException;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

/**
 * Validates the tokens of the provider: the signature with its keys (fetched
 * again when a token uses a key not seen yet, i.e. after a key rotation), the
 * issuer, the audience (this client) and the dates.
 *
 * - ID token (sign-in): also the nonce of the sign-in and the authorized party,
 *   as OpenID Connect Core 3.1.3.7 asks. It comes straight from the token
 *   endpoint over TLS, which the spec accepts in place of the signature check;
 *   the signature is checked anyway.
 * - Access token (API): issued to any client of the realm (a mobile app, a
 *   script) but for this app, which the audience says.
 */
final readonly class TokenValidator
{
    /** Keycloak's "typ" claim of the tokens that must never be taken for another kind. */
    private const array NOT_ACCESS_TOKENS = ['ID', 'Refresh', 'Logout'];

    public function __construct(
        private OidcClient $client,
        private ClockInterface $clock,
        /** Clock skew tolerated on "iat", "nbf" and "exp", in seconds. */
        private int $leeway = 30,
    ) {
    }

    /**
     * @return array<string, mixed> the claims of the token
     */
    public function validateIdToken(string $idToken, string $expectedNonce): array
    {
        $claims = $this->validate($idToken);

        // "azp" is required when the token has several audiences, and must be
        // this client whenever it is present.
        $clientId = $this->client->getClientId();
        $audience = $claims['aud'];
        $authorizedParty = $claims['azp'] ?? null;
        if ((\is_array($audience) && \count($audience) > 1 && null === $authorizedParty)
            || (null !== $authorizedParty && $authorizedParty !== $clientId)) {
            throw new OidcException(\sprintf('The ID token was issued to "%s", not to this client.', \is_string($authorizedParty) ? $authorizedParty : 'another party'));
        }
        $nonce = $claims['nonce'] ?? null;
        if (!\is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
            throw new OidcException('The ID token nonce does not match the sign-in request.');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed> the claims of the token
     */
    public function validateAccessToken(string $accessToken): array
    {
        $claims = $this->validate($accessToken);
        // An ID token has this app as its audience too: it is not an access token.
        $type = $claims['typ'] ?? null;
        if (\in_array($type, self::NOT_ACCESS_TOKENS, true)) {
            throw new OidcException(\sprintf('A "%s" token is not an access token.', $type));
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>
     */
    private function validate(string $token): array
    {
        $jws = $this->parse($token);
        if (!$this->verifySignature($jws, $this->client->getSigningKeys())
            && !$this->verifySignature($jws, $this->client->getSigningKeys(refresh: true))) {
            throw new OidcException('The token signature does not match any key of the identity provider.');
        }

        $payload = json_decode((string) $jws->getPayload(), true);
        if (!\is_array($payload) || array_is_list($payload)) {
            throw new OidcException('The token payload is not a JSON object.');
        }
        /** @var array<string, mixed> $claims */
        $claims = $payload;
        $checker = new ClaimCheckerManager([
            new IssuerChecker([$this->client->getIssuer()]),
            new AudienceChecker($this->client->getClientId()),
            new ExpirationTimeChecker(clock: $this->clock, allowedTimeDrift: $this->leeway),
            new IssuedAtChecker(clock: $this->clock, allowedTimeDrift: $this->leeway),
            new NotBeforeChecker(clock: $this->clock, allowedTimeDrift: $this->leeway),
        ]);
        try {
            $checker->check($claims, ['iss', 'sub', 'aud', 'exp', 'iat']);
        } catch (\Throwable $e) {
            throw new OidcException(\sprintf('The token is not valid: %s', $e->getMessage()), 0, $e);
        }
        if (!\is_string($claims['sub']) || '' === $claims['sub']) {
            throw new OidcException('The token "sub" is empty.');
        }

        return $claims;
    }

    private function parse(string $token): JWS
    {
        try {
            $jws = (new CompactSerializer())->unserialize($token);
        } catch (\InvalidArgumentException $e) {
            throw new OidcException('The token is not a compact JWS.', 0, $e);
        }
        if (1 !== $jws->countSignatures()) {
            throw new OidcException('The token must carry exactly one signature.');
        }
        $algorithm = $jws->getSignature(0)->getProtectedHeaderParameter('alg');
        if (!\is_string($algorithm) || !$this->algorithms()->has($algorithm)) {
            throw new OidcException(\sprintf('The token is signed with "%s", which is not accepted.', \is_string($algorithm) ? $algorithm : get_debug_type($algorithm)));
        }

        return $jws;
    }

    private function verifySignature(JWS $jws, JWKSet $keys): bool
    {
        if (0 === $keys->count()) {
            return false;
        }
        $verifier = new JWSVerifier($this->algorithms());
        try {
            // web-token/jwt-library >= 4.3 replaces verifyWithKeySet() with verify().
            if (method_exists($verifier, 'verify')) { // @phpstan-ignore function.impossibleType
                $result = $verifier->verify($jws, $keys, 0);

                return \is_object($result) && method_exists($result, 'isVerified') && true === $result->isVerified();
            }

            return $verifier->verifyWithKeySet($jws, $keys, 0);
        } catch (\Throwable) {
            return false;
        }
    }

    private function algorithms(): AlgorithmManager
    {
        return new AlgorithmManager([
            new RS256(), new RS384(), new RS512(),
            new PS256(), new PS384(), new PS512(),
            new ES256(), new ES384(), new ES512(),
        ]);
    }
}
