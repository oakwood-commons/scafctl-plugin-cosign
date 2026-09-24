# scafctl-plugin-cosign

A scafctl provider plugin for in-process OCI artifact signing with embedded cosign/sigstore libraries. Sign an already-pushed artifact by digest, store the signature as an OCI 1.1 referrer, optionally log it to a Rekor transparency log — without a `cosign` binary, a container runtime, or a statically managed key in CI.

This is the **sign half** of a daemonless push-then-sign flow. Pair it with the `oci` provider: `push` / `push-artifact` publishes the content, `cosign` signs the published digest.

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

`key` accepts everything cosign's key references support: an encrypted cosign key file (`cosign generate-key-pair` format), `env://VAR` holding a PEM, `k8s://namespace/secret` (secret with `cosign.key`/`cosign.password` data), and KMS references (`gcpkms://`, `awskms://`, `azurekms://`, `hashivault://`).

Password-protected keys read their password from the `COSIGN_PASSWORD` environment variable — the plugin never prompts, so CI must not hang on an interactive prompt.

### Keyless identity

Keyless signing signs with an ephemeral key and an OIDC-issued Fulcio certificate, so **no statically managed key** exists at all. Fulcio requires a raw OIDC ID token (audience `sigstore`); the plugin sources one in this order:

1. **Ambient OIDC providers** (no configuration): `SIGSTORE_ID_TOKEN`, GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` and `id-token: write` permission), SPIFFE workload identity, and the other providers cosign supports.
2. **`oidc_handler`**: the scafctl host auth broker is asked for a token from that handler and the token is presented to Fulcio. This only works when your Fulcio deployment trusts that handler's token issuer/audience — it is a deployment property, not a guarantee. Until the SDK grows a first-class OIDC identity API (issue #1), ambient providers are the supported path.

If neither yields a token, signing fails with an error explaining the options. Keyless additionally requires `fulcio_url`; with the default `tlog_upload: true` it also requires `rekor_url` (keyless verification depends on the tlog entry because the certificate is short-lived).

> **No endpoint is hardcoded.** Public-good URLs (fulcio.sigstore.dev, rekor.sigstore.dev) are used only where you write them. For private sigstore deployments, pass your own endpoints; set `fulcio_insecure_skip_verify: true` if your Fulcio's CT log keys aren't in the public TUF root.

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

AC #1 interoperability is not gated on a `cosign` binary: `TestSign_VerifiesWithCosignLibraries_OCI11` (and the legacy-mode twin) signs through the plugin and verifies through cosign's own `VerifyImageSignatures` with `ExperimentalOCI11` — the identical code path `cosign verify --registry-referrers-mode oci-1-1` runs, invoked as a library. The tests run in normal CI on any machine.

### Live-endpoint tests (env-gated)

Keyless signing against live sigstore endpoints is the only part that needs real infrastructure:

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
