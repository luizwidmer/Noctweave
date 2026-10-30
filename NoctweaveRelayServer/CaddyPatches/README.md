# Caddy go-jose/v3 security backports

Caddy 2.11.7's TLS module transitively imports
`github.com/go-jose/go-jose/v3@v3.0.5` through Smallstep. That v3 release is
affected by three advisories, and the v3 line has no upstream patched release:

- [GHSA-mgcc-cww5-fp2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-mgcc-cww5-fp2q) / CVE-2026-116587: [upstream commit a0111f8](https://github.com/go-jose/go-jose/commit/a0111f82742fa92bceec9ede40845e73319e6230) bounds RSA JWK modulus size, checks prime factors, and rejects private JWK/EPK material before key validation. The v3 backport also assigns general JWS unprotected headers before merging and validates every JWE header source so a private key cannot hide behind another header.
- [GHSA-vvm8-gf78-28g4](https://github.com/go-jose/go-jose/security/advisories/GHSA-vvm8-gf78-28g4) / CVE-2026-116586: [upstream commit b382393](https://github.com/go-jose/go-jose/commit/b382393402cac5a9f1f1b641a4bab4ce70ca1bae) limits JSON nesting depth to 10,000.
- [GHSA-4w3g-jfj2-cw2q](https://github.com/go-jose/go-jose/security/advisories/GHSA-4w3g-jfj2-cw2q) / CVE-2026-116585: [upstream commit 1f9bcda](https://github.com/go-jose/go-jose/commit/1f9bcda36b115c6c46592ac97551f0b6447775a4) rejects invalid CBC-HMAC key sizes, and [commit 35883f7](https://github.com/go-jose/go-jose/commit/35883f7999e87cbd1b1f4cda07fdad8cd71c3dd6) rejects empty ciphertext before unpadding.

`Dockerfile.caddy-l4` downloads checksum-verified v3.0.5 source with Go,
applies `go-jose-v3-rsa-limit.patch` to a private build copy, runs the affected
upstream package tests plus RSA, hostile JWS/JWE header, JSON depth, and CBC-HMAC
regressions, and uses that copy as the v3 module
replacement when compiling the Caddy binary. The upstream module's Apache-2.0
license and the embedded JSON scanner's BSD notice stay with the build copy.
No source is served or installed in the final image. The same Docker build pins
`github.com/go-chi/chi/v5@v5.4.0` for
[CVE-2026-114437](https://github.com/advisories/GHSA-j6qf-3m9c-vwj3).

The v3 parsing APIs do not accept caller-provided algorithm allow lists, so the
v4 commit's allowed-algorithm ordering changes do not map to v3 without an API
change. The v3 JWE parser checks that `alg` and `enc` are present before it
parses embedded key material; all embedded keys receive the early public-only
check regardless of algorithm.

Keep the patch and release gate until upstream publishes a patched v3 release
or Caddy/Smallstep removes the v3 import. Trivy identifies the locally
replaced module by its build path without a release version, so its otherwise
clean scan cannot establish that the source actually contains these fixes. The
release gate must also check this patch's pinned digest and the exact final
binary's `caddy build-info` replacement metadata. Other HIGH/CRITICAL
findings remain release blockers.
