package cosign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey is a cosign key pair materialized on disk for key-based tests.
type testKey struct {
	path     string // encrypted private key PEM file path
	pubPEM   []byte // PEM of the public half
	sv       signature.SignerVerifier
	password string
}

// writeTestKey generates an ephemeral key pair and writes the private half
// as an encrypted cosign key file, the same format `cosign generate-key-pair`
// produces.
func writeTestKey(t *testing.T) *testKey {
	t.Helper()
	privKey, err := pkgcosign.GeneratePrivateKey()
	require.NoError(t, err)

	plainPEM, err := cryptoutils.MarshalPrivateKeyToPEM(privKey)
	require.NoError(t, err)

	password := "unit-test-password"
	plainPath := filepath.Join(t.TempDir(), "plain.key")
	require.NoError(t, os.WriteFile(plainPath, plainPEM, 0600))

	// Encrypt into the cosign "ENCRYPTED COSIGN PRIVATE KEY" format.
	kb, err := pkgcosign.ImportKeyPair(plainPath, func(bool) ([]byte, error) { return []byte(password), nil })
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "cosign.key")
	require.NoError(t, os.WriteFile(keyPath, kb.PrivateBytes, 0600))

	sv, err := pkgcosign.LoadPrivateKey(kb.PrivateBytes, []byte(password), nil)
	require.NoError(t, err)

	t.Setenv("COSIGN_PASSWORD", password)
	return &testKey{path: keyPath, pubPEM: kb.PublicBytes, sv: sv, password: password}
}

func setupRegistry(t *testing.T) (*httptest.Server, *Plugin) {
	t.Helper()
	reg := registry.New()
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	return srv, &Plugin{}
}

// pushRandomImage pushes a small random image to the test registry under
// repoTag and returns its digest.
func pushRandomImage(t *testing.T, srv *httptest.Server, repoTag string) string {
	t.Helper()
	ref, err := name.ParseReference(registryRef(srv, repoTag))
	require.NoError(t, err)

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	require.NoError(t, remote.Write(ref, img))
	d, err := img.Digest()
	require.NoError(t, err)
	return d.String()
}

// pushMultiArchIndex pushes a two-child index under repoTag and returns the
// index digest and the child digests.
func (s registryState) pushMultiArchIndex(t *testing.T, repoTag string) (string, []string) {
	t.Helper()
	ref, err := name.ParseReference(registryRef(s.srv, repoTag))
	require.NoError(t, err)

	idx := v1.ImageIndex(empty.Index)
	for _, plat := range []v1.Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
	} {
		img, ierr := random.Image(256, 1)
		require.NoError(t, ierr)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &plat},
		})
	}
	require.NoError(t, remote.WriteIndex(ref, idx))

	id, err := idx.Digest()
	require.NoError(t, err)
	m, err := idx.IndexManifest()
	require.NoError(t, err)
	children := make([]string, 0, len(m.Manifests))
	for _, c := range m.Manifests {
		children = append(children, c.Digest.String())
	}
	return id.String(), children
}

type registryState struct {
	srv *httptest.Server
}

// sign executes the sign operation against the plugin and returns output data.
//
//nolint:revive // test helper: t must be first
func sign(t *testing.T, ctx context.Context, p *Plugin, input map[string]any) map[string]any {
	t.Helper()
	out, err := p.ExecuteProvider(ctx, ProviderName, input)
	require.NoError(t, err)
	require.NotNil(t, out)
	data, ok := out.Data.(map[string]any)
	require.True(t, ok, "expected map output data, got %T", out.Data)
	return data
}

func registryRef(srv *httptest.Server, repoTag string) string {
	return fmt.Sprintf("%s/%s", srv.Listener.Addr().String(), repoTag)
}

// referrerManifest fetches and decodes a raw referrer manifest by digest.
func referrerManifest(t *testing.T, repo name.Repository, digest string) map[string]any {
	t.Helper()
	desc, err := remote.Get(repo.Digest(digest))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(desc.Manifest, &m))
	return m
}

// assertSignature verifies the signature attached to subjectDigest: it
// re-derives the expected payload, checks the referrer manifest shape, and
// verifies the embedded signature against the key in-process.
func assertSignature(t *testing.T, srv *httptest.Server, repo string, subjectDigest string, key *testKey, annotations map[string]string) {
	t.Helper()

	repoRef, err := name.NewRepository(registryRef(srv, repo))
	require.NoError(t, err)

	idx, err := remote.Referrers(repoRef.Digest(subjectDigest))
	require.NoError(t, err)
	m, err := idx.IndexManifest()
	require.NoError(t, err)

	// Re-derive the expected payload for the subject digest.
	digestRef := repoRef.Digest(subjectDigest)
	expectedPayload, err := (&sigpayload.Cosign{
		Image:       digestRef,
		Annotations: payloadAnnotations(annotations),
	}).MarshalJSON()
	require.NoError(t, err)
	payloadDigest := "sha256:" + fmt.Sprintf("%x", sha256.Sum256(expectedPayload))

	var found map[string]any
	for _, r := range m.Manifests {
		rm := referrerManifest(t, repoRef, r.Digest.String())
		layers, _ := rm["layers"].([]any)
		if len(layers) == 0 {
			continue
		}
		l0, _ := layers[0].(map[string]any)
		if l0["digest"] == payloadDigest {
			found = rm
			break
		}
	}
	require.NotNilf(t, found, "no referrer for %s carries the signature payload %s", subjectDigest, payloadDigest)

	// Referrer shape: cosign signature type, subject set to the signed digest.
	assert.Equal(t, cosignSignatureArtifactType, found["artifactType"], "referrer artifactType")
	assert.Equal(t, cosignSignatureArtifactType, nestedMediaType(found, "config"))
	subject, _ := found["subject"].(map[string]any)
	require.NotNil(t, subject)
	assert.Equal(t, subjectDigest, subject["digest"])

	// And the layer descriptor digest matches the payload we signed.
	layers, _ := found["layers"].([]any)
	require.NotEmpty(t, layers)
	l0, _ := layers[0].(map[string]any)
	assert.Equal(t, payloadDigest, l0["digest"])

	// The embedded signature must verify in-process against the key.
	anns, _ := l0["annotations"].(map[string]any)
	b64sig, _ := anns["dev.cosignproject.cosign/signature"].(string)
	require.NotEmpty(t, b64sig, "signature annotation")
	sigBytes, err := base64.StdEncoding.DecodeString(b64sig)
	require.NoError(t, err)
	require.NoError(t, key.sv.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(expectedPayload)),
		"signature must verify against the signing key")
}

// nestedMediaType digs out manifest.config.mediaType.
func nestedMediaType(m map[string]any, field string) string {
	cfg, _ := m[field].(map[string]any)
	if cfg == nil {
		return ""
	}
	s, _ := cfg["mediaType"].(string)
	return s
}

func TestSign_KeyBased_CreatesReferrer(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()

	digest := pushRandomImage(t, srv, "myorg/myapp:v1")
	before, err := remote.Head(mustParseDigestRef(t, srv, "myorg/myapp", digest))
	require.NoError(t, err)

	data := sign(t, ctx, p, map[string]any{
		"operation":   OpSign,
		"ref":         registryRef(srv, "myorg/myapp:v1"),
		"key":         key.path,
		"annotations": map[string]any{"org.opencontainers.image.source": "https://github.com/myorg/myapp"},
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, digest, data["digest"])
	assert.Equal(t, ReferrersModeOCI11, data["referrers_mode"])
	assert.NotEmpty(t, data["signature_digest"], "signature_digest must be reported")
	assert.NotContains(t, data, "tlog_index", "no tlog upload without rekor_url")
	assert.NotContains(t, data, "certificate", "no certificate for key-based signing")
	assert.Len(t, data["signed_digests"], 1)

	assertSignature(t, srv, "myorg/myapp", digest, key,
		map[string]string{"org.opencontainers.image.source": "https://github.com/myorg/myapp"})

	// Subject integrity: signing must not mutate or re-push the subject.
	after, err := remote.Head(mustParseDigestRef(t, srv, "myorg/myapp", digest))
	require.NoError(t, err)
	assert.Equal(t, before.Digest, after.Digest, "subject digest must be unchanged")
}

func TestSign_DigestRefInput(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()

	digest := pushRandomImage(t, srv, "myorg/myapp:v1")

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSign,
		"ref":       fmt.Sprintf("%s@%s", registryRef(srv, "myorg/myapp"), digest),
		"key":       key.path,
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, digest, data["digest"])
	assertSignature(t, srv, "myorg/myapp", digest, key, nil)
}

func TestSign_KeyBased_LegacyMode(t *testing.T) {
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

	assert.Equal(t, true, data["success"])
	assert.Equal(t, ReferrersModeLegacy, data["referrers_mode"])

	// The signature must live at the sha256-<digest>.sig tag.
	digestRef := mustParseDigestRef(t, srv, "myorg/myapp", digest)
	sigTag, err := ociremote.SignatureTag(digestRef)
	require.NoError(t, err)
	sigDesc, err := remote.Get(sigTag)
	require.NoError(t, err, "legacy signature tag must exist")
	assert.Equal(t, data["signature_digest"], sigDesc.Digest.String())

	var sigManifest map[string]any
	require.NoError(t, json.Unmarshal(sigDesc.Manifest, &sigManifest))
	layers, _ := sigManifest["layers"].([]any)
	require.NotEmpty(t, layers)

	// The signature image carries the base64 signature annotation.
	expectedPayload, err := (&sigpayload.Cosign{Image: digestRef}).MarshalJSON()
	require.NoError(t, err)
	l0, _ := layers[0].(map[string]any)
	assert.Equal(t, "sha256:"+fmt.Sprintf("%x", sha256.Sum256(expectedPayload)), l0["digest"])
	anns, _ := l0["annotations"].(map[string]any)
	b64sig, _ := anns["dev.cosignproject.cosign/signature"].(string)
	require.NotEmpty(t, b64sig)
	sigBytes, err := base64.StdEncoding.DecodeString(b64sig)
	require.NoError(t, err)
	require.NoError(t, key.sv.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(expectedPayload)))
}

func TestSign_KeyBased_DedupesOnResign(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()

	pushRandomImage(t, srv, "myorg/myapp:v1")
	input := map[string]any{
		"operation":      OpSign,
		"ref":            registryRef(srv, "myorg/myapp:v1"),
		"key":            key.path,
		"referrers_mode": "legacy",
	}

	first := sign(t, ctx, p, input)
	second := sign(t, ctx, p, input)

	// In legacy mode the dupe detector sees the tag-stored signature, so
	// re-signing the same payload with the same key must not stack a
	// duplicate layer: the signature image digest is unchanged.
	//
	// In oci-1-1 referrers mode, signatures are only discoverable through
	// the referrers API, which the dupe detector cannot see, so repeat
	// signs append new referrers — matching cosign's own behavior. Until
	// superseded-referrer GC lands (issue #4), consumers should treat
	// referrer multiplicity as a known artifact of re-signing.
	assert.Equal(t, first["signature_digest"], second["signature_digest"],
		"legacy re-sign must dedupe the signature layer")
	assert.Equal(t, first["digest"], second["digest"])
}

func TestSign_Recursive_MultiArch(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()
	state := registryState{srv: srv}

	indexDigest, children := state.pushMultiArchIndex(t, "myorg/index:v1")

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSign,
		"ref":       registryRef(srv, "myorg/index:v1"),
		"key":       key.path,
		"recursive": true,
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, indexDigest, data["digest"])

	want := map[string]bool{indexDigest: true}
	for _, c := range children {
		want[c] = true
	}
	got, _ := data["signed_digests"].([]string)
	require.Len(t, got, len(want))
	for _, d := range got {
		assert.True(t, want[d], "unexpected signed digest %s", d)
	}

	// Every child carries its own signature referrer.
	assertSignature(t, srv, "myorg/index", indexDigest, key, nil)
	for _, c := range children {
		assertSignature(t, srv, "myorg/index", c, key, nil)
	}
}

func TestSign_NonRecursive_MultiArchSignsIndexOnly(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()
	state := registryState{srv: srv}

	indexDigest, children := state.pushMultiArchIndex(t, "myorg/index:v1")

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSign,
		"ref":       registryRef(srv, "myorg/index:v1"),
		"key":       key.path,
	})

	assert.Equal(t, indexDigest, data["digest"])
	got, _ := data["signed_digests"].([]string)
	require.Len(t, got, 1)

	// Children are not signed without recursive: no child digest may carry
	// a cosign signature referrer.
	repoRef, err := name.NewRepository(registryRef(srv, "myorg/index"))
	require.NoError(t, err)
	for _, c := range children {
		idx, ierr := remote.Referrers(repoRef.Digest(c))
		if ierr != nil {
			// No referrers listing at all is a pass for this assertion.
			continue
		}
		m, merr := idx.IndexManifest()
		if merr != nil {
			continue
		}
		for _, r := range m.Manifests {
			rm := referrerManifest(t, repoRef, r.Digest.String())
			assert.NotEqual(t, cosignSignatureArtifactType, nestedMediaType(rm, "config"),
				"child digest must not be signed without recursive")
		}
	}
}

func TestSign_ExecutionErrors(t *testing.T) {
	srv, p := setupRegistry(t)
	key := writeTestKey(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		input   map[string]any
		wantErr string
	}{
		{
			name:    "missing ref",
			input:   map[string]any{"operation": OpSign, "key": "k"},
			wantErr: `"ref"`,
		},
		{
			name: "unknown registry",
			input: map[string]any{
				"operation": OpSign,
				"ref":       "localhost:1/nonexistent/app:v1",
				"key":       key.path,
			},
			wantErr: "resolving",
		},
		{
			name: "invalid path plus",
			input: map[string]any{
				"operation": OpSign,
				"ref":       registryRef(srv, "myorg/ap+p:v1"),
				"key":       key.path,
			},
			wantErr: "'+'",
		},
		{
			name: "missing key file",
			input: map[string]any{
				"operation": OpSign,
				"ref":       registryRef(srv, "myorg/myapp:v1"),
				"key":       "/nonexistent/cosign.key",
			},
			wantErr: "loading key",
		},
		{
			name: "keyless without identity",
			input: map[string]any{
				"operation":    OpSign,
				"ref":          registryRef(srv, "myorg/myapp:v1"),
				"fulcio_url":   "https://fulcio.invalid",
				"tlog_upload":  false,
				"oidc_handler": "",
			},
			wantErr: "OIDC identity",
			// gated: no ambient provider is expected in unit tests; if the
			// runner happens to provide one, Fulcio at .invalid still fails
			// with a different error, so only require some error below.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ExecuteProvider(ctx, ProviderName, tt.input)
			require.Error(t, err)
			if tt.wantErr != "" && tt.name != "keyless without identity" {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestSign_Keyless_AmbientToken exercises the keyless signing path when an
// ambient OIDC token is present (the SIGSTORE_ID_TOKEN provider), against a
// live Fulcio + Rekor. It is skipped unless the environment provides the
// endpoints, per the issue's integration-gating note.
func TestSign_Keyless_AmbientToken(t *testing.T) {
	fulcioURL := os.Getenv("COSIGN_TEST_FULCIO_URL")
	rekorURL := os.Getenv("COSIGN_TEST_REKOR_URL")
	if fulcioURL == "" || rekorURL == "" {
		t.Skip("set COSIGN_TEST_FULCIO_URL and COSIGN_TEST_REKOR_URL to run the keyless integration test")
	}

	srv, p := setupRegistry(t)
	ctx := context.Background()
	digest := pushRandomImage(t, srv, "myorg/myapp:v1")

	t.Setenv("SIGSTORE_ID_TOKEN", os.Getenv("COSIGN_TEST_ID_TOKEN"))

	data := sign(t, ctx, p, map[string]any{
		"operation":                   OpSign,
		"ref":                         registryRef(srv, "myorg/myapp:v1"),
		"fulcio_url":                  fulcioURL,
		"rekor_url":                   rekorURL,
		"fulcio_insecure_skip_verify": os.Getenv("COSIGN_TEST_SKIP_FULCIO_VERIFY") == "true",
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, digest, data["digest"])
	assert.NotEmpty(t, data["certificate"], "keyless signing reports the Fulcio certificate")
	assert.Contains(t, data, "tlog_index", "keyless signing uploads to the tlog by default")
	assert.Contains(t, data, "tlog_url")
}

func BenchmarkSign(b *testing.B) {
	// Silence the registry's request logging: it interleaves with benchmark
	// output and breaks benchstat parsing in the PR benchmark comparison.
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(reg)
	defer srv.Close()

	keyPath := benchKey(b)

	img, err := random.Image(256, 1)
	if err != nil {
		b.Fatal(err)
	}
	ref, err := name.ParseReference(registryRef(srv, "bench/app:v1"))
	if err != nil {
		b.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		b.Fatal(err)
	}

	p := &Plugin{}
	ctx := context.Background()
	input := map[string]any{
		"operation": OpSign,
		"ref":       ref.String(),
		"key":       keyPath,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.ExecuteProvider(ctx, ProviderName, input); err != nil {
			b.Fatal(err)
		}
	}
}

// benchKey writes an encrypted cosign key to disk for benchmarks.
func benchKey(b *testing.B) string {
	b.Helper()
	privKey, err := pkgcosign.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	plainPEM, err := cryptoutils.MarshalPrivateKeyToPEM(privKey)
	if err != nil {
		b.Fatal(err)
	}
	password := "bench-password"
	plainPath := filepath.Join(b.TempDir(), "plain.key")
	if err := os.WriteFile(plainPath, plainPEM, 0600); err != nil {
		b.Fatal(err)
	}
	kb, err := pkgcosign.ImportKeyPair(plainPath, func(bool) ([]byte, error) { return []byte(password), nil })
	if err != nil {
		b.Fatal(err)
	}
	keyPath := filepath.Join(b.TempDir(), "cosign.key")
	if err := os.WriteFile(keyPath, kb.PrivateBytes, 0600); err != nil {
		b.Fatal(err)
	}
	b.Setenv("COSIGN_PASSWORD", password)
	return keyPath
}

// mustParseDigestRef parses <registry>/<repo>@sha256:... for test assertions.
func mustParseDigestRef(t *testing.T, srv *httptest.Server, repo, digest string) name.Digest {
	t.Helper()
	ref, err := name.ParseReference(fmt.Sprintf("%s@%s", registryRef(srv, repo), digest))
	require.NoError(t, err)
	d, ok := ref.(name.Digest)
	require.True(t, ok, "expected a digest reference")
	return d
}
