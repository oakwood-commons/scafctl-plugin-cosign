# scafctl-plugin-cosign

A scafctl provider plugin for in-process signing with embedded cosign/sigstore libraries. Sign an already-pushed OCI artifact by digest (signature stored as an OCI 1.1 referrer), sign a plain blob with a detached signature (checksum files, tarballs), verify blob signatures against a public key or a pinned keyless identity — without a `cosign` binary, a container runtime, or a statically managed key in CI.

This plugin covers the **signing half** of a daemonless push-then-sign flow. Pair it with the `oci` provider: `push` / `push-artifact` publishes the content, `cosign` signs the published digest — and `sign-blob` / `verify-blob` cover the non-container release artifacts (signing `SHA256SUMS`, goreleaser-style assets).

## Names

| Surface | Value |
|---------|-------|
| Repository | `scafctl-plugin-cosign` |
| Go module | `github.com/oakwood-commons/scafctl-plugin-cosign` |
| Binary | `scafctl-plugin-cosign` |
| Provider name | `cosign` |
| Catalog artifact | `cosign` |

The **provider name** is what users reference in solutions (`provider: cosign`).

## Operations

| Operation | Description |
|-----------|-------------|
| `sign` | Sign a pushed artifact by digest and attach the signature to the registry (OCI 1.1 referrer or legacy tag) |
| `sign-blob` | Sign a plain blob (checksum file, tarball) and write a detached signature, plus an optional legacy or sigstore bundle |
| `verify-blob` | Verify a detached blob signature against a public key or a pinned keyless identity/issuer; a failure stops the pipeline |

Signing blobs needs no registry: the credential chain and `registry`-scoped settings apply to `sign` only. Verifying OCI image signatures in-process is planned separately (issue #7).

## Installation

```bash
# Install from catalog
scafctl plugins install cosign

# Or build and install locally
task release:local VERSION=0.1.0
```

## Authentication

Signing **pushes** the signature artifact, so the plugin must authenticate to the subject's registry. It uses the same layered credential chain as the `oci` provider (see its README for details):

| # | Source | When it applies |
|---|--------|-----------------|
| 1 | Explicit settings | `username`/`password` in solution config |
| 2 | scafctl credential store | After `scafctl catalog login <registry>` |
| 3 | Docker/Podman config | `~/.docker/config.json` fallback |
| 4 | Host broker | Solution context with `scafctl auth login` (auto-detects the handler per registry) |
| 5 | Anonymous | Public registries |

### Settings

| Setting | Type | Description |
|---------|------|-------------|
| `registry` | string | Registry hostname for credential scoping |
| `username` | string | Explicit username |
| `password` | string | Explicit password or token |
| `auth_handler` | string | Force a specific auth handler (e.g. `acme-quay`) |
| `scope` | string | OAuth scope override |
| `insecure` | bool | Allow HTTP (non-TLS) registries for dev/localhost/air-gapped environments |

## Operation Reference

### `sign`

Sign the artifact identified by `ref` and attach the signature to its registry.

A digest ref (`repo@sha256:...`) is signed as-is; a tag ref (`repo:tag`) is resolved to its digest first, and the **digest** is what gets signed — the subject manifest is never mutated or re-pushed.

| Input | Required | Description |
|-------|----------|-------------|
| `ref` | yes | Artifact to sign (digest or tag reference) |
| `key` | no | cosign key reference for **key-based** signing: a file path, `env://VAR`, `k8s://namespace/secret`, or a KMS reference. Omit for keyless |
| `keyless` | no | Force keyless (OIDC) signing. Defaults to `true` when `key` is absent; cannot be combined with `key` |
| `oidc_handler` | no | scafctl auth handler to source the OIDC identity from when no ambient provider is available (see [Keyless identity](#keyless-identity)) |
| `fulcio_url` | no* | Fulcio CA that issues the ephemeral signing certificate. *Required for keyless |
| `rekor_url` | no | Transparency-log endpoint. No default is hardcoded — configure your deployment's endpoint |
| `tlog_upload` | no | Upload the signature to Rekor. Default: `true` for keyless (verification needs the tlog entry), `true` for key-based when `rekor_url` is given, `false` otherwise |
| `referrers_mode` | no | `oci-1-1` (default): signature stored as an OCI 1.1 referrer artifact. `legacy`: signature stored under the tag-based `sha256-<digest>.sig` scheme |
| `annotations` | no | Signature annotations, embedded in the signed payload (map or comma-separated `key=value` string) |
| `recursive` | no | Also sign the child manifests of a multi-arch index (the index digest is always signed) |
| `fulcio_insecure_skip_verify` | no | Skip Fulcio's client-side SCT verification — needed for private Fulcio deployments whose CT log keys are not in the public sigstore TUF root |
| `retry` | no | Retry tuning for the signature registry writes. Accepts `true` (defaults), an attempt count, or `{ attempts, backoff, maxBackoff }` |

**Output**: `success`, `ref`, `digest` (signed subject manifest), `mediaType`, `signature_digest` (the signature referrer manifest in `oci-1-1` mode, or the signature image in `legacy` mode), `signed_digests` (all digests signed — subject plus children when `recursive`), `referrers_mode`, and when uploaded `tlog_index` / `tlog_url`, and for keyless `certificate` (the Fulcio-issued PEM).

```bash
# Key-based: sign the digest an oci provider push just produced
scafctl run provider cosign operation=sign \
  ref=ghcr.io/myorg/myapp@sha256:abc123... \
  key=./cosign.key

# Keyless with the public-good sigstore infrastructure (CI with ambient OIDC)
scafctl run provider cosign operation=sign \
  ref=ghcr.io/myorg/myapp:latest \
  fulcio_url=https://fulcio.sigstore.dev \
  rekor_url=https://rekor.sigstore.dev

# Legacy tag-based storage instead of OCI 1.1 referrers
scafctl run provider cosign operation=sign \
  ref=ghcr.io/myorg/myapp:latest key=./cosign.key referrers_mode=legacy
```

### Key-based signing

`key` accepts everything cosign's key references support: an encrypted cosign key file (`cosign generate-key-pair` format), `env://VAR` holding a PEM, `k8s://namespace/secret` (secret with `cosign.key`/`cosign.password` data), and KMS references (`gcpkms://`, `awskms://`, `azurekms://`, `hashivault://`). The KMS backends are linked into the plugin binary, so KMS references are resolved by the sigstore libraries **in-process** — no external helper binaries. Any other `scheme://` key reference is rejected with a clear error rather than falling through to sigstore's external-program KMS fallback, keeping the no-shell guarantee. (Hardware tokens (`pkcs11:`) and `gitlab://` references are not supported in this build; `env://` and `http(s)://` references follow sigstore's own loader behavior, including its optional plugin-binary extension probe for those two schemes only.)

Password-protected keys read their password from the `COSIGN_PASSWORD` environment variable — the plugin never prompts, so CI must not hang on an interactive prompt.

### Keyless identity

Keyless signing signs with an ephemeral key and an OIDC-issued Fulcio certificate, so **no statically managed key** exists at all. Fulcio requires a raw OIDC ID token (audience `sigstore`); the plugin sources one in this order:

1. **Ambient OIDC providers** (no configuration): `SIGSTORE_ID_TOKEN`, GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` and `id-token: write` permission), SPIFFE workload identity, and the other providers cosign supports.
2. **`oidc_handler`**: the scafctl host auth broker is asked for a token from that handler and the token is presented to Fulcio. This only works when your Fulcio deployment trusts that handler's token issuer/audience — it is a deployment property, not a guarantee. Until the SDK grows a first-class OIDC identity API (issue #1), ambient providers are the supported path.

If neither yields a token, signing fails with an error explaining the options. Keyless additionally requires `fulcio_url`; with the default `tlog_upload: true` it also requires `rekor_url` (keyless verification depends on the tlog entry because the certificate is short-lived).

> **No endpoint is hardcoded.** Public-good URLs (fulcio.sigstore.dev, rekor.sigstore.dev) are used only where you write them. For private sigstore deployments, pass your own endpoints; set `fulcio_insecure_skip_verify: true` if your Fulcio's CT log keys aren't in the public TUF root.

### `sign-blob`

Sign a plain blob — a checksum file, a tarball, any bytes — and produce a detached signature, mirroring `cosign sign-blob` in-process. The blob comes from exactly one of `path` (a local file, streamed through the signer once; never fully buffered) or `content` (inline). The same signing identities as `sign` apply: key file, `env://`, `k8s://`, KMS, or keyless.

| Input | Required | Description |
|-------|----------|-------------|
| `path` / `content` | one of the two | Blob source: a local file path, or inline content |
| `key` | no | cosign key reference (same as `sign`). Omit for keyless |
| `keyless` | no | Force keyless signing (same semantics as `sign`) |
| `oidc_handler` | no | scafctl auth handler for the OIDC identity (see [Keyless identity](#keyless-identity)) |
| `fulcio_url` | no* | Fulcio CA (required for keyless) |
| `rekor_url` | no | Transparency-log endpoint; same defaulting as `sign` |
| `tlog_upload` | no | Upload the signature to Rekor. Default: `true` for keyless, `true` for key-based when `rekor_url` is given, `false` otherwise |
| `output_signature` | no | File to write the detached **base64** signature to (the format `cosign verify-blob` expects) |
| `output_certificate` | no | File to write the Fulcio certificate PEM to (keyless only) |
| `bundle` | no | File to write a signature bundle to (see `bundle_format`) |
| `bundle_format` | no | `legacy` (default): cosign's `--bundle` JSON. `sigstore`: the protobuf bundle (`--new-bundle-format`) |
| `fulcio_insecure_skip_verify` | no | Skip Fulcio's SCT verification (private deployments, same as `sign`) |

**Output**: `success`, `digest` (`sha256:...` of the blob), `signature` (base64), `certificate` (PEM, keyless), `signature_path` / `certificate_path` / `bundle_path` / `bundle_format` when files were written, and `tlog_index` / `tlog_url` when uploaded.

```bash
# Key-based: sign a checksum file the way a release pipeline would
scafctl run provider cosign operation=sign-blob \
  path=./dist/SHA256SUMS key=./cosign.key \
  output_signature=./dist/SHA256SUMS.sig \
  bundle=./dist/SHA256SUMS.bundle

# Keyless (goreleaser-style), signing to stdout-adjacent files
scafctl run provider cosign operation=sign-blob \
  path=./dist/app.tar.gz \
  fulcio_url=https://fulcio.sigstore.dev rekor_url=https://rekor.sigstore.dev \
  output_signature=./dist/app.tar.gz.sig bundle_format=sigstore bundle=./dist/app.tar.sigstore.bundle
```

The output verifies with the stock tooling: `cosign verify-blob --key cosign.pub --signature dist/SHA256SUMS.sig dist/SHA256SUMS` (interop is covered by tests that sign through the plugin and verify through cosign's own command code)

### `verify-blob`

Verify a detached blob signature and stop the pipeline on failure — pin-and-assert before publishing. Mirrors `cosign verify-blob` in-process against a public key (key-based) or a certificate + pinned identity/issuer (keyless), optionally with a bundle.

| Input | Required | Description |
|-------|----------|-------------|
| `path` / `content` | one of the two | Blob source: a local file path, or inline content |
| `key` | see note | Public key reference: file, `env://`, `k8s://`, or KMS. Exclusive with `certificate` |
| `certificate` | see note | PEM certificate to verify a keyless signature against |
| `signature` | one source | Inline base64 signature; or `signature_path` (base64 or raw bytes file); or the `bundle`'s embedded signature |
| `signature_path` | one source | File holding the signature |
| `bundle` | one source / no | Legacy JSON or sigstore protobuf bundle: verification material source |
| `bundle_format` | no | `legacy` (default) or `sigstore`; `sigstore` requires `bundle` and `trusted_root` |
| `certificate_identity` | keyless* | Expected identity in the signing certificate (or `certificate_identity_regexp`) |
| `certificate_oidc_issuer` | keyless* | Expected OIDC issuer (or `certificate_oidc_issuer_regexp`) |
| `ca_roots` / `ca_intermediates` / `certificate_chain` | no | PEM trust anchors for private Fulcio deployments (legacy path) |
| `trusted_root` | no | sigstore `trusted_root.json`; required with `bundle_format: sigstore` |
| `rekor_url` | no | Rekor endpoint for the transparency-log check |
| `ignore_tlog` | no | Skip the transparency-log check (needed for key-based signatures with no tlog entry) |

**Output**: `success`, `verified: true`, `digest` (`sha256:...` of the blob), `bundle_verified` (offline bundle verification happened). A failed verification returns an **error** — the assert — so the workflow stops.

Exactly one of `key`, `certificate`, or `bundle` must provide the trust anchor. Keyless checking (a certificate, or a bundle carrying one) always requires the identity + issuer pair, exactly like cosign.

```bash
# Key-based assert in a pipeline: wrong key, tampered blob, or tampered
# signature all fail the action
scafctl run provider cosign operation=verify-blob \
  path=./dist/SHA256SUMS key=./cosign.pub \
  signature_path=./dist/SHA256SUMS.sig ignore_tlog=true

# Keyless assert: certificate, pinned identity and issuer, tlog checked
scafctl run provider cosign operation=verify-blob \
  path=./dist/app.tar.gz \
  certificate=./dist/app.cert.pem \
  certificate_identity="release-bot@example.com" \
  certificate_oidc_issuer=https://token.actions.githubusercontent.com \
  rekor_url=https://rekor.sigstore.dev \
  signature_path=./dist/app.tar.gz.sig
```

> **Trust data.** Without explicit trust anchors, keyless verification fetches sigstore's public trust material (Fulcio roots, CT log and Rekor keys) through the TUF client — a network fetch cached under `~/.sigstore` / `~/.cache/sigstore`. For private deployments, pass `ca_roots`/`ca_intermediates`/`certificate_chain` (legacy path) or a `trusted_root` file (sigstore bundle path) instead.

### Verification compatibility

Signatures are written by cosign's own OCI write path, so the output verifies with the standard tooling:

```bash
# OCI 1.1 referrers (default mode)
cosign verify --key cosign.pub --registry-referrers-mode oci-1-1 ghcr.io/myorg/myapp@sha256:abc123...
cosign verify --registry-referrers-mode oci-1-1 ghcr.io/myorg/myapp@sha256:abc123...   # keyless: certificate + tlog

# Legacy mode
cosign verify --key cosign.pub ghcr.io/myorg/myapp@sha256:abc123...
```

Known behavior (matching the cosign CLI): re-signing the same payload with the same key **deduplicates** in `legacy` mode via the signature-tag dupe detector, but `oci-1-1` referrers accumulate on repeat signs — cosign's dupe detector cannot see referrer-stored signatures. Superseded-referrer garbage collection is tracked as a follow-up (issue #4).

Blob signatures follow the same interop rule: `sign-blob` output verifies with stock `cosign verify-blob` (signature file, legacy `--bundle`, or `--new-bundle-format` bundle). In-process OCI `verify` is tracked separately (issue #7).

## Usage

### Solution

```yaml
spec:
  workflow:
    actions:
      push-image:
        provider: oci
        inputs:
          operation: push
          ref: ghcr.io/myorg/myapp:v1
          path: ./dist/image.tar

      sign-image:
        provider: cosign
        # The sign action resolves the tag ref to its digest first — the
        # digest is what gets signed, so reusing the push ref is safe.
        inputs:
          operation: sign
          ref: ghcr.io/myorg/myapp:v1
          key: env://COSIGN_SIGNING_KEY
          annotations:
            org.opencontainers.image.source: https://github.com/myorg/myapp
```

See `examples/sign.yaml` for a runnable push-artifact → sign chain.

## Development

```bash
task test        # Run tests
task lint        # Run linter
task build       # Build binary
task ci          # Full CI pipeline (lint + test + build)
task bench       # Run benchmarks
```

### Verification interop, tested in-process

AC #1 interoperability is not gated on a `cosign` binary:

- For `sign`, `TestSign_VerifiesWithCosignLibraries_OCI11` (and the legacy-mode twin) signs through the plugin and verifies through cosign's own `VerifyImageSignatures` — the identical code path `cosign verify --registry-referrers-mode oci-1-1` runs, invoked as a library.
- For `sign-blob` / `verify-blob`, `TestSignBlob_VerifiesWithCosignVerifyBlob` and friends sign through the plugin and verify through cosign's own `VerifyBlobCmd` — the code behind `cosign verify-blob`. KMS-referenced keys are covered the same way through sigstore's in-memory fake KMS (`fakekms://`), over the same registration path the real KMS backends use. The sigstore protobuf-bundle verify path is covered offline too, against sigstore-go's virtual sigstore as the trusted root (`TestVerifyBlob_BundleSigstore_KeyBased`).

The tests run in normal CI on any machine; only the libraries change, never a binary.

### Live-endpoint tests (env-gated)

Keyless signing against live sigstore endpoints is the only part that needs real infrastructure — for `sign` (`TestSign_Keyless_AmbientToken`), `sign-blob` (`TestSignBlob_Keyless_AmbientToken`), and keyless `verify-blob` (`TestVerifyBlob_Keyless_AmbientToken`):

```bash
COSIGN_TEST_FULCIO_URL=https://fulcio.sigstore.dev \
COSIGN_TEST_REKOR_URL=https://rekor.sigstore.dev \
COSIGN_TEST_ID_TOKEN=... go test -run TestSign_Keyless ./...
```

## Local Testing

```bash
# Build and install as a local catalog artifact
task release:local VERSION=0.1.0

# Run a sample solution
scafctl run solution -f examples/sign.yaml
```

## Release

```bash
task release:tag VERSION=0.1.0
```

This creates a signed git tag and pushes it. The CI release workflow runs tests, builds binaries for all platforms, publishes the plugin artifact to the catalog, signs the catalog artifact, and refreshes the catalog index.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
