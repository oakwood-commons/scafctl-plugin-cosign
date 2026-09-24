package cosign

import (
	"context"
	"net/http/httptest"
	"testing"

	ggcRemote "github.com/google/go-containerregistry/pkg/v1/remote"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyWithCosignLibraries runs cosign's own in-process verification
// (VerifyImageSignatures) against the signatures this plugin wrote — the same
// code path `cosign verify` executes, invoked as a library instead of a
// binary. Proving interop here keeps the whole chain shell-free and runnable
// in normal CI on any machine.
//
//nolint:revive // test helper: t must be first
func verifyWithCosignLibraries(t *testing.T, ctx context.Context, srv *httptest.Server, repo, digest string, key *testKey, oci11 bool) {
	t.Helper()
	digestRef := mustParseDigestRef(t, srv, repo, digest)
	co := &pkgcosign.CheckOpts{
		SigVerifier:       key.sv,
		ClaimVerifier:     pkgcosign.SimpleClaimVerifier,
		IgnoreTlog:        true,
		Offline:           true,
		ExperimentalOCI11: oci11,
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(ggcRemote.WithContext(ctx)),
		},
	}
	signatures, bundleVerified, err := pkgcosign.VerifyImageSignatures(ctx, digestRef, co)
	require.NoError(t, err, "cosign library verify (ExperimentalOCI11=%v) must pass", oci11)
	require.NotEmpty(t, signatures, "expected at least one verified signature")
	assert.False(t, bundleVerified, "tlog verification is skipped offline")
}

// TestSign_VerifiesWithCosignLibraries_OCI11 proves AC #1 in-process: the
// signature this plugin writes as an OCI 1.1 referrer verifies through
// cosign's own referrers-mode verification path — the same code behind
// `cosign verify --registry-referrers-mode oci-1-1`.
func TestSign_VerifiesWithCosignLibraries_OCI11(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()
	digest := pushRandomImage(t, srv, "myorg/myapp:v1")

	data := sign(t, ctx, p, map[string]any{
		"operation":   OpSign,
		"ref":         registryRef(srv, "myorg/myapp:v1"),
		"key":         key.path,
		"annotations": map[string]any{"org.opencontainers.image.source": "https://github.com/myorg/myapp"},
	})
	require.Equal(t, true, data["success"])
	require.Equal(t, ReferrersModeOCI11, data["referrers_mode"])

	verifyWithCosignLibraries(t, ctx, srv, "myorg/myapp", digest, key, true)
}

// TestSign_VerifiesWithCosignLibraries_Legacy proves the legacy-mode
// signature image verifies through cosign's tag-based verification path —
// the code behind `cosign verify` without the referrers flag.
func TestSign_VerifiesWithCosignLibraries_Legacy(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()
	digest := pushRandomImage(t, srv, "myorg/myapp:v1")

	data := sign(t, ctx, p, map[string]any{
		"operation":      OpSign,
		"ref":            registryRef(srv, "myorg/myapp:v1"),
		"key":            key.path,
		"referrers_mode": "legacy",
	})
	require.Equal(t, true, data["success"])
	require.Equal(t, ReferrersModeLegacy, data["referrers_mode"])

	verifyWithCosignLibraries(t, ctx, srv, "myorg/myapp", digest, key, false)
}
