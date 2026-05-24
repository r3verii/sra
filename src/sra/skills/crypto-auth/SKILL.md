# Skill — audit/crypto-auth (v0)

Investigates one packet under `.audit/04-packets-sensors/audit-crypto-auth/`.

## Inputs
- The single packet given in the prompt.
- The target repository, reachable from cwd.

## Tools allowed
- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN
- `Write`, `Edit`, `NotebookEdit`, `Bash`, any network tool.

## What the skill does

Crypto-auth audit asks five questions:

1. **Algorithm choice**: are the cipher / KDF / hash / signature
   algorithms appropriate for the use case? (Don't blanket-flag
   `MD5` — it's fine for non-security checksums.)
2. **Verification correctness**: is signature / MAC / JWT verification
   performed and BEFORE acting on the payload? Are there fail-open /
   early-return paths?
3. **Randomness**: is the RNG cryptographically secure where it
   matters (keys, nonces, session IDs, tokens, CSRF)?
4. **Constant-time compares**: are HMAC / token / signature equalities
   done in constant time?
5. **Configuration / defaults**: weak ciphers permitted? Renegotiation
   allowed? Insecure protocol versions? Hardcoded secrets / keys?

Hits categorised by `expected_role`:
- `crypto_import` — library / module use
- `jwt_api` — JWT sign/verify/decode
- `password_hash` — bcrypt / argon2 / scrypt / pbkdf2
- `weak_rng` — non-crypto RNG (`Math.random`, `random.random`, `math/rand`, `java.util.Random`)
- `compare` — equality APIs (concern when comparing secrets)

For each packet:

1. **Library identification**: which crypto libraries are in use? Open
   `requirements.txt` / `package.json` / `go.mod` / `Cargo.toml`
   adjacent to the cluster.

2. **Per `jwt_api` hit**:
   - Is it `verify()` or `decode()`? `decode()` without verification is
     almost always a bug.
   - What algorithm whitelist is passed? `alg: 'none'` or `alg: 'HS256'`
     accepted when the issuer signs with RS256 = algorithm-confusion.
   - Is the key the right type (HMAC key vs RSA public key)?
   - **Findings to look for**: missing algorithm whitelist; using
     `decode` instead of `verify`; verifying against attacker-influenced
     `kid` lookups; missing audience / issuer claims check.

3. **Per `password_hash` hit**:
   - Cost factor / rounds: bcrypt ≥ 10, argon2 modern params, pbkdf2 ≥
     600k SHA-256 (NIST 2023).
   - Is the salt application-managed or library-managed?
   - **Findings to look for**: cost factor too low, hashing weakened
     for migration but never raised, sha1/sha256 single-pass used as
     password hash.

4. **Per `weak_rng` hit**:
   - What is the random value used for?
     - UI dither, retry jitter, sampling → fine
     - Token, key, nonce, session ID, CSRF, ID enumeration defense → bug
   - **Findings to look for**: weak RNG used for any security-relevant
     value.

5. **Per `compare` hit**:
   - What's being compared?
     - File paths, status codes, type tags → benign
     - HMAC, signature, token, password hash, MFA code → must be
       constant-time
   - **Findings to look for**: `===` / `memcmp` / `strcmp` on secret
     comparison.

6. **Configuration review**:
   - TLS config: protocol versions, cipher suites, renegotiation
     setting
   - Hardcoded secrets: search for `key = "...".`, `secret = "...".`,
     `password = "...".`
   - Algorithm strings: `"AES/ECB"`, `"DES"`, `"RC4"`, `"MD5withRSA"`,
     `"SHA1withRSA"` are red flags.

7. **For each potential issue**:
   - Cite `file:line`.
   - Explain the cryptographic property that fails.
   - Smallest fix.

8. **For each dismissed hit**:
   - One sentence.

9. **For unknowns**:
   - Protocol-level misuse that requires runtime tracing
   - Key material loaded at runtime
   - Configuration overrides at deployment

## What the skill MUST NOT do

- Do not flag `MD5` or `SHA1` unconditionally. Check the use case.
- Do not flag every comparison. Check what's compared.
- Do not flag library use absent specific misuse.
- Do not extrapolate to other families.
- Be honest: many real crypto bugs are protocol-level (nonce reuse,
  algorithm confusion, downgrade); these often need expert review
  and may not be visible in a single packet.

## Output

Print to STDOUT. Standard schema.

## Failure modes the skill should report explicitly

- "All JWT calls use `verify()` with explicit `algorithms=['RS256']`.
  No `decode()` without verify found."
- "Password hashing uses bcrypt with cost factor 12. NIST 2023 OK."
- "All compares of secret material go through
  `crypto.timingSafeEqual` / `hmac.compare_digest`."
- "I could not determine the TLS cipher-suite list because it is
  configured at deployment time outside this cluster."
- "Algorithm choice looks correct, but I cannot prove freedom from
  nonce-reuse without runtime inspection of the IV / nonce
  derivation across all callers."

## Why this contract exists

Crypto is the family where false positives are most expensive
(you don't want to "fix" working code) and false negatives are
most expensive (you don't want to ship broken crypto). The skill
must be conservative on dismissals and explicit when it cannot
prove a property statically.
