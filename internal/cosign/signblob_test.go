package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cosignopts "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	fakekms "github.com/sigstore/sigstore/pkg/signature/kms/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyBlobWithCosign runs cosign's own verify-blob command (the same code
// `cosign verify-blob` executes) against a signature this plugin produced,
// proving AC #1 interop in-process: no cosign binary exists here, only the
// library the CLI itself calls.
//
//nolint:revive // test helper: t must be first
func verifyBlobWithCosign(t *testing.T, ctx context.Context, blobPath, keyPath, sigPath string, bundlePath string, newBundleFormat bool) {
	t.Helper()
	cmd := &verify.VerifyBlobCmd{
		KeyOpts: cosignopts.KeyOpts{
			KeyRef:          keyPath,
			BundlePath:      bundlePath,
			NewBundleFormat: newBundleFormat,
		},
		SigRef:        sigPath,
		IgnoreTlog:    true,
		HashAlgorithm: crypto.SHA256,
	}
	require.NoError(t, cmd.Exec(ctx, blobPath), "cosign library verify-blob must pass")
}

// writeBlobFile writes content to a temp file and returns its path.
func writeBlobFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// blobDigest returns the sha256 digest of b, the shape sign-blob reports.
func blobDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// decodeSig decodes and returns the base64 signature from output data.
func decodeSig(t *testing.T, data map[string]any) []byte {
	t.Helper()
	sigB64, ok := data["signature"].(string)
	require.True(t, ok, "signature must be reported as a base64 string")
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	require.NoError(t, err, "signature must be valid base64")
	return sig
}

// TestSignBlob_KeyBased_DetachedSignature proves the plugin's own round
// trip: sign a file, check the reported digest and the detached signature.
func TestSignBlob_KeyBased_DetachedSignature(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blob := "abc123  release.tar.gz\ndef456  extra.bin\n"
	blobPath := writeBlobFile(t, "SHA256SUMS", blob)
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSignBlob,
		"path":      blobPath,
		"key":       key.path,
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, blobPath, data["path"])
	assert.Equal(t, blobDigest([]byte(blob)), data["digest"])

	sig := decodeSig(t, data)
	require.NoError(t, key.sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte(blob))))
}

// TestSignBlob_VerifiesWithCosignVerifyBlob proves AC #1: a signature this
// plugin writes verifies through cosign's own verify-blob path with the
// public key --- the identical semantics consumers get from the CLI.
func TestSignBlob_VerifiesWithCosignVerifyBlob(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "SHA256SUMS", "abc123  release.tar.gz\n")
	sigPath := filepath.Join(t.TempDir(), "SHA256SUMS.sig")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation":        OpSignBlob,
		"content":          "abc123  release.tar.gz\n",
		"key":              key.path,
		"output_signature": sigPath,
	})

	assert.Equal(t, sigPath, data["signature_path"])
	sigOnDisk, err := os.ReadFile(sigPath) //nolint:gosec // test temp file built from t.TempDir()
	require.NoError(t, err)
	assert.Equal(t, data["signature"], string(sigOnDisk), "signature file holds the same base64 signature")

	verifyBlobWithCosign(t, ctx, blobPath, pubPath, sigPath, "", false)
}

// TestSignBlob_BundleLegacy_RoundTrips proves the legacy bundle (cosign
// sign-blob --bundle JSON) loads with cosign's own reader and verifies
// through the stock verify-blob path using the bundle alone.
func TestSignBlob_BundleLegacy_RoundTrips(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "SHA256SUMS", "abc123  release.tar.gz\n")
	bundlePath := filepath.Join(t.TempDir(), "SHA256SUMS.bundle")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSignBlob,
		"path":      blobPath,
		"key":       key.path,
		"bundle":    bundlePath,
	})

	lsp, err := pkgcosign.FetchLocalSignedPayloadFromPath(bundlePath)
	require.NoError(t, err, "legacy bundle must load with cosign's own reader")
	assert.Equal(t, data["signature"], lsp.Base64Signature)
	assert.Empty(t, lsp.Cert, "key-based signing writes no certificate")
	assert.Equal(t, BundleFormatLegacy, data["bundle_format"])

	// cosign verify-blob accepts the bundle in place of the signature file.
	verifyBlobWithCosign(t, ctx, blobPath, pubPath, "", bundlePath, false)
}

// TestSignBlob_BundleSigstore_KeyBased proves the sigstore protobuf bundle:
// cosign's own bundle loader reads it back, the recorded digest matches the
// blob, and the embedded signature verifies against the key.
func TestSignBlob_BundleSigstore_KeyBased(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blob := "abc123  release.tar.gz\n"
	blobPath := writeBlobFile(t, "SHA256SUMS", blob)
	bundlePath := filepath.Join(t.TempDir(), "SHA256SUMS.sigstore.bundle")
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation":     OpSignBlob,
		"path":          blobPath,
		"key":           key.path,
		"bundle":        bundlePath,
		"bundle_format": BundleFormatSigstore,
	})
	assert.Equal(t, BundleFormatSigstore, data["bundle_format"])

	b, err := sgbundle.LoadJSONFromPath(bundlePath)
	require.NoError(t, err, "sigstore bundle must load with sigstore-go's reader")
	sc, err := b.SignatureContent()
	require.NoError(t, err)
	msc := sc.MessageSignatureContent()
	sum := sha256.Sum256([]byte(blob))
	assert.Equal(t, sum[:], msc.Digest(), "bundle digest must be the blob's sha256")
	assert.Equal(t, "SHA2_256", msc.DigestAlgorithm())

	sig := decodeSig(t, data)
	assert.Equal(t, sig, msc.Signature(), "bundle carries the same signature")
	require.NoError(t, key.sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader([]byte(blob))))
}

// TestSignBlob_KMS_FakeKMS proves AC #2's KMS half in-process: signing with
// a KMS-style key reference (sigstore's in-memory fake KMS registers the
// same way the real backends do) produces a signature the public half and
// cosign's stock verify-blob both accept.
func TestSignBlob_KMS_FakeKMS(t *testing.T) {
	priv, err := pkgcosign.GeneratePrivateKey()
	require.NoError(t, err)
	// Register a private key in the fake KMS through the context; the plugin
	// resolves key "fakekms://test-key" via the same kms.Get path as the real
	// backends.
	ctx := context.WithValue(context.Background(), fakekms.KmsCtxKey{}, priv)

	blob := "contents of a release artifact\n"
	blobPath := writeBlobFile(t, "checksums.txt", blob)
	sigPath := filepath.Join(t.TempDir(), "checksums.txt.sig")
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(&priv.PublicKey)
	require.NoError(t, err)
	pubPath := writeBlobFile(t, "cosign.pub", string(pubPEM))
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation":        OpSignBlob,
		"path":             blobPath,
		"key":              "fakekms://test-key",
		"output_signature": sigPath,
	})

	sig := decodeSig(t, data)
	digest := sha256.Sum256([]byte(blob))
	assert.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig), "KMS signature must verify with the public key")

	verifyBlobWithCosign(t, ctx, blobPath, pubPath, sigPath, "", false)
}

// TestSignBlob_ContentInline proves the content input path: no temp files,
// the digest matches the content.
func TestSignBlob_ContentInline(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	content := "{\"schema\": \"inline\"}\n"
	p := &Plugin{}

	data := sign(t, ctx, p, map[string]any{
		"operation": OpSignBlob,
		"content":   content,
		"key":       key.path,
	})

	assert.Equal(t, true, data["success"])
	assert.Equal(t, blobDigest([]byte(content)), data["digest"])
	assert.NotContains(t, data, "path", "inline content reports no path")
}

// TestSignBlob_Keyless_AmbientToken exercises keyless blob signing against
// live Fulcio + Rekor (the same env gating as the sign keyless test): the
// certificate, the tlog entry, and a cert-bearing legacy bundle all come
// back.
func TestSignBlob_Keyless_AmbientToken(t *testing.T) {
	fulcioURL := os.Getenv("COSIGN_TEST_FULCIO_URL")
	rekorURL := os.Getenv("COSIGN_TEST_REKOR_URL")
	if fulcioURL == "" || rekorURL == "" {
		t.Skip("set COSIGN_TEST_FULCIO_URL and COSIGN_TEST_REKOR_URL to run the keyless blob integration test")
	}

	blobPath := writeBlobFile(t, "SHA256SUMS", "abc123  release.tar.gz\n")
	bundlePath := filepath.Join(t.TempDir(), "SHA256SUMS.bundle")
	certPath := filepath.Join(t.TempDir(), "SHA256SUMS.cert.pem")
	p := &Plugin{}
	ctx := context.Background()

	t.Setenv("SIGSTORE_ID_TOKEN", os.Getenv("COSIGN_TEST_ID_TOKEN"))

	data := sign(t, ctx, p, map[string]any{
		"operation":                   OpSignBlob,
		"path":                        blobPath,
		"fulcio_url":                  fulcioURL,
		"rekor_url":                   rekorURL,
		"bundle":                      bundlePath,
		"output_certificate":          certPath,
		"fulcio_insecure_skip_verify": os.Getenv("COSIGN_TEST_SKIP_FULCIO_VERIFY") == "true",
	})

	assert.Equal(t, true, data["success"])
	assert.NotEmpty(t, data["certificate"], "keyless signing reports the Fulcio certificate")
	assert.Contains(t, string(data["certificate"].(string)), "BEGIN CERTIFICATE")
	require.Contains(t, data, "tlog_index", "keyless signing uploads to the tlog by default")
	assert.Contains(t, data, "tlog_url")

	lsp, err := pkgcosign.FetchLocalSignedPayloadFromPath(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, data["signature"], lsp.Base64Signature)
	assert.NotEmpty(t, lsp.Cert, "keyless legacy bundle carries the certificate")

	certOnDisk, err := os.ReadFile(certPath) //nolint:gosec // test temp file built from t.TempDir()
	require.NoError(t, err)
	assert.Equal(t, data["certificate"], string(certOnDisk), "certificate file matches the reported PEM")
}

// TestSignBlob_Errors locks the validation surface of sign-blob.
func TestSignBlob_Errors(t *testing.T) {
	key := writeTestKey(t)
	blobPath := writeBlobFile(t, "checksums.txt", "data\n")
	p := &Plugin{}
	ctx := context.Background()

	tests := []struct {
		name    string
		input   map[string]any
		wantErr string
	}{
		{
			name:    "missing path and content",
			input:   map[string]any{"operation": OpSignBlob, "key": key.path},
			wantErr: `required fields "path"`,
		},
		{
			name: "both path and content",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "content": "x", "key": key.path,
			},
			wantErr: "set only one of path or content, not both",
		},
		{
			name: "invalid bundle_format",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "key": key.path,
				"bundle": "b.json", "bundle_format": "proto",
			},
			wantErr: `invalid bundle_format "proto"`,
		},
		{
			name: "sigstore format requires bundle output",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "key": key.path,
				"bundle_format": BundleFormatSigstore,
			},
			wantErr: "bundle_format sigstore requires the bundle output path",
		},
		{
			name: "output_certificate with key-based signing",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "key": key.path,
				"output_certificate": "cert.pem",
			},
			wantErr: "output_certificate requires keyless signing",
		},
		{
			name: "unknown key scheme rejected by the guard",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "key": "mykms://key",
			},
			wantErr: `unsupported key scheme "mykms"`,
		},
		{
			name: "keyless without fulcio",
			input: map[string]any{
				"operation": OpSignBlob, "path": blobPath, "keyless": true,
			},
			wantErr: "fulcio_url is required for keyless signing",
		},
		{
			name: "nonexistent blob file",
			input: map[string]any{
				"operation": OpSignBlob, "path": filepath.Join(t.TempDir(), "missing"), "key": key.path,
			},
			wantErr: "sign-blob: opening blob",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ExecuteProvider(ctx, ProviderName, tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// BenchmarkSignBlob measures the hot path: sign a 64 KiB inline blob with a
// key-based identity (per the repo benchmarking convention for provider
// operations).
func BenchmarkSignBlob(b *testing.B) {
	keyPath := benchKey(b)
	p := &Plugin{}
	ctx := context.Background()
	blob := strings.Repeat("benchmark payload line\n", 2730) // ~64 KiB
	input := map[string]any{
		"operation": OpSignBlob,
		"content":   blob,
		"key":       keyPath,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.ExecuteProvider(ctx, ProviderName, input); err != nil {
			b.Fatal(err)
		}
	}
}
