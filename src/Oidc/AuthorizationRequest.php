<?php

declare(strict_types=1);

namespace Issl\SsoBundle\Oidc;

/**
 * One sign-in in progress: the secrets sent to (or derived for) the identity
 * provider, kept in the session until the provider redirects back.
 *
 * - state:         ties the callback to this browser session (CSRF).
 * - nonce:         ties the ID token to this sign-in (replay).
 * - code verifier: PKCE; only its SHA-256 hash leaves the server, so a stolen
 *                  authorization code is useless without it.
 */
final readonly class AuthorizationRequest
{
    public function __construct(
        public string $state,
        public string $nonce,
        public string $codeVerifier,
        public int $createdAt,
        /** Relative path to return to once signed in. */
        public ?string $targetPath = null,
        /** True for a background check of the provider session (prompt=none). */
        public bool $silent = false,
    ) {
    }

    public static function create(int $now, ?string $targetPath = null, bool $silent = false): self
    {
        return new self(self::randomToken(32), self::randomToken(32), self::randomToken(48), $now, $targetPath, $silent);
    }

    /**
     * PKCE "S256" challenge: BASE64URL(SHA256(code_verifier)), RFC 7636 4.2.
     */
    public function codeChallenge(): string
    {
        return self::base64UrlEncode(hash('sha256', $this->codeVerifier, true));
    }

    /**
     * @return array{state: string, nonce: string, code_verifier: string, created_at: int, target_path: ?string, silent: bool}
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'created_at' => $this->createdAt,
            'target_path' => $this->targetPath,
            'silent' => $this->silent,
        ];
    }

    public static function fromArray(mixed $data): ?self
    {
        if (!\is_array($data)) {
            return null;
        }
        $state = $data['state'] ?? null;
        $nonce = $data['nonce'] ?? null;
        $codeVerifier = $data['code_verifier'] ?? null;
        $createdAt = $data['created_at'] ?? null;
        $targetPath = $data['target_path'] ?? null;
        if (!\is_string($state) || !\is_string($nonce) || !\is_string($codeVerifier) || !\is_int($createdAt)) {
            return null;
        }

        return new self($state, $nonce, $codeVerifier, $createdAt, \is_string($targetPath) ? $targetPath : null, true === ($data['silent'] ?? false));
    }

    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param int<1, max> $bytes
     */
    private static function randomToken(int $bytes): string
    {
        return self::base64UrlEncode(random_bytes($bytes));
    }
}
