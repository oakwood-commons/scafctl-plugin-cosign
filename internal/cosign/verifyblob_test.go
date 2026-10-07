package cosign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signBlob is a test convenience: run sign-blob through the plugin and return
// the output data.
//
//nolint:revive // test helper: t must be first
func signBlob(t *testing.T, ctx context.Context, p *Plugin, input map[string]any) map[string]any {
	t.Helper()
	input["operation"] = OpSignBlob
	return sign(t, ctx, p, input)
}

// writeSigFile writes a base64 signature file and returns its path.
func writeSigFile(t *testing.T, sigB64 string) string {
	t.Helper()
	return writeBlobFile(t, "blob.sig", sigB64)
}

// TestVerifyBlob_KeyBased_OK proves the pin-and-assert happy path: sign a
// blob with the plugin, verify it with the plugin against the public key,
// inline and via signature_path.
func TestVerifyBlob_KeyBased_OK(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "SHA256SUMS", "abc123  release.tar.gz\n")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signData := signBlob(t, ctx, p, map[string]any{
		"path": blobPath,
		"key":  key.path,
	})

	for _, tt := range []struct {
		name  string
		extra map[string]any
	}{
		{name: "inline signature", extra: map[string]any{"signature": signData["signature"]}},
		{name: "signature file", extra: map[string]any{"signature_path": writeSigFile(t, signData["signature"].(string))}},
		{name: "inline content instead of a path", extra: map[string]any{
			"__drop_path__": true,
			"content":       "abc123  release.tar.gz\n",
			"signature":     signData["signature"],
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := map[string]any{
				"operation":   OpVerifyBlob,
				"path":        blobPath,
				"key":         pubPath,
				"ignore_tlog": true,
			}
			for k, v := range tt.extra {
				if k == "__drop_path__" {
					delete(input, "path")
					continue
				}
				input[k] = v
			}
			data := sign(t, ctx, p, input)
			assert.Equal(t, true, data["verified"])
			assert.Equal(t, blobDigest([]byte("abc123  release.tar.gz\n")), data["digest"])
		})
	}
}

// TestVerifyBlob_WrongKey_Fails locks AC #3: a signature checked against the
// wrong public key must fail, and a failed verification surfaces as an error
// that stops the pipeline.
func TestVerifyBlob_WrongKey_Fails(t *testing.T) {
	signingKey := writeTestKey(t)
	wrongKey := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "checksums.txt", "tamper-proof content\n")
	wrongPub := writeBlobFile(t, "wrong.pub", string(wrongKey.pubPEM))
	p := &Plugin{}

	signData := signBlob(t, ctx, p, map[string]any{
		"path": blobPath,
		"key":  signingKey.path,
	})

	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation":   OpVerifyBlob,
		"path":        blobPath,
		"key":         wrongPub,
		"signature":   signData["signature"],
		"ignore_tlog": true,
	})
	require.Error(t, err, "verification with the wrong key must fail")
	assert.Contains(t, err.Error(), "verify-blob")
}

// TestVerifyBlob_TamperedBlob_Fails locks AC #3: any modification of the
// blob between signing and verification must be detected.
func TestVerifyBlob_TamperedBlob_Fails(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "SHA256SUMS", "original content\n")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signData := signBlob(t, ctx, p, map[string]any{
		"path": blobPath,
		"key":  key.path,
	})

	tamperedPath := writeBlobFile(t, "SHA256SUMS", "original content, tampered\n")
	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation":   OpVerifyBlob,
		"path":        tamperedPath,
		"key":         pubPath,
		"signature":   signData["signature"],
		"ignore_tlog": true,
	})
	require.Error(t, err, "a tampered blob must fail verification")
}

// TestVerifyBlob_TamperedSignature_Fails locks AC #3: a corrupted signature
// must fail verification, not pass silently.
func TestVerifyBlob_TamperedSignature_Fails(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "checksums.txt", "steady content\n")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signBlob(t, ctx, p, map[string]any{
		"path": blobPath,
		"key":  key.path,
	})

	// A different valid base64 string: decodes, verifies false.
	tamperedSig := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation":   OpVerifyBlob,
		"path":        blobPath,
		"key":         pubPath,
		"signature":   tamperedSig,
		"ignore_tlog": true,
	})
	require.Error(t, err, "a tampered signature must fail verification")
}

// TestVerifyBlob_BundleLegacy_KeyBased verifies through a legacy bundle
// produced by the plugin's own sign-blob: the bundle substitutes for the
// signature file.
func TestVerifyBlob_BundleLegacy_KeyBased(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blobPath := writeBlobFile(t, "SHA256SUMS", "bundled content\n")
	bundlePath := filepath.Join(t.TempDir(), "SHA256SUMS.bundle")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signBlob(t, ctx, p, map[string]any{
		"path":   blobPath,
		"key":    key.path,
		"bundle": bundlePath,
	})

	data := sign(t, ctx, p, map[string]any{
		"operation":   OpVerifyBlob,
		"path":        blobPath,
		"key":         pubPath,
		"bundle":      bundlePath,
		"ignore_tlog": true,
	})
	assert.Equal(t, true, data["verified"])
}

// TestVerifyBlob_Errors locks the validation surface of verify-blob.
func TestVerifyBlob_Errors(t *testing.T) {
	key := writeTestKey(t)
	blobPath := writeBlobFile(t, "checksums.txt", "data\n")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	bundlePath := filepath.Join(t.TempDir(), "b.bundle")
	p := &Plugin{}
	ctx := context.Background()

	tests := []struct {
		name    string
		input   map[string]any
		wantErr string
	}{
		{
			name:    "missing path and content",
			input:   map[string]any{"operation": OpVerifyBlob, "key": pubPath},
			wantErr: `required fields "path"`,
		},
		{
			name: "no verifier provided",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
			},
			wantErr: "provide a key, a certificate to verify against, or a bundle",
		},
		{
			name: "key and certificate conflict",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"key":         pubPath,
				"certificate": "cert.pem",
			},
			wantErr: "set only one of key or certificate, not both",
		},
		{
			name: "identity pinning with a key",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"certificate_identity": "signer@example.com",
			},
			wantErr: "apply to certificate or bundle verification only",
		},
		{
			name: "both signature sources",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"signature": "aGk=", "signature_path": "sig.b64",
			},
			wantErr: "set only one of signature or signature_path, not both",
		},
		{
			name: "sigstore bundle without trusted root",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"bundle": bundlePath, "bundle_format": BundleFormatSigstore,
			},
			wantErr: "trusted_root is required when bundle_format is sigstore",
		},
		{
			name: "sigstore format without bundle",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"bundle_format": BundleFormatSigstore, "trusted_root": "trusted_root.json",
			},
			wantErr: "bundle is required when bundle_format is sigstore",
		},
		{
			name: "trusted root on the legacy path",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"trusted_root": "trusted_root.json",
			},
			wantErr: "trusted_root is only supported with bundle_format sigstore",
		},
		{
			name: "keyless bundle without identity pinning",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"bundle": bundlePath,
			},
			wantErr: "certificate_identity or certificate_identity_regexp is required",
		},
		{
			name: "keyless without issuer",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"bundle": bundlePath, "certificate_identity": "signer@example.com",
			},
			wantErr: "certificate_oidc_issuer or certificate_oidc_issuer_regexp is required",
		},
		{
			name: "invalid ignore_tlog",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"ignore_tlog": "maybe",
			},
			wantErr: "invalid ignore_tlog",
		},
		{
			name: "key scheme rejected by the guard",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath,
				"key": "mykms://pub",
			},
			wantErr: `unsupported key scheme "mykms"`,
		},
		{
			name: "nonexistent blob",
			input: map[string]any{
				"operation": OpVerifyBlob,
				"path":      filepath.Join(t.TempDir(), "missing"),
				"key":       pubPath, "ignore_tlog": true,
			},
			wantErr: "reading blob",
		},
		{
			name: "signature not base64",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"signature": "%%not-base64%%", "ignore_tlog": true,
			},
			wantErr: "signature must be base64-encoded",
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

// TestVerifyBlob_ErrorPrefixOnce guards against double-prefixing: helper
// errors reach the user only through the single outer wrap, so every
// verify-blob error carries the "verify-blob" prefix exactly once.
func TestVerifyBlob_ErrorPrefixOnce(t *testing.T) {
	key := writeTestKey(t)
	blobPath := writeBlobFile(t, "checksums.txt", "data\n")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}
	ctx := context.Background()

	tests := []struct {
		name    string
		input   map[string]any
		wantSub string
	}{
		{
			name: "signature not base64",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"signature": "%%not-base64%%", "ignore_tlog": true,
			},
			wantSub: "signature must be base64-encoded",
		},
		{
			name: "no signature source",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"ignore_tlog": true,
			},
			wantSub: `required field "signature", "signature_path", or "bundle" is missing`,
		},
		{
			name: "signature file missing",
			input: map[string]any{
				"operation": OpVerifyBlob, "path": blobPath, "key": pubPath,
				"signature_path": filepath.Join(t.TempDir(), "missing.sig"),
				"ignore_tlog":    true,
			},
			wantSub: "reading signature file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ExecuteProvider(ctx, ProviderName, tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantSub)
			assert.True(t, strings.HasPrefix(err.Error(), "verify-blob: "),
				"error should carry the outer prefix: %q", err.Error())
			assert.Equal(t, 1, strings.Count(err.Error(), "verify-blob"),
				"verify-blob prefix must appear exactly once: %q", err.Error())
		})
	}
}

// TestVerifyBlob_TempFileCleanup ensures inline content sign→verify works
// end to end (the temp blob file is created and cleaned up transparently).
func TestVerifyBlob_TempFileCleanup(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	content := "e2e inline\n"
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signData := signBlob(t, ctx, p, map[string]any{"content": content, "key": key.path})

	data := sign(t, ctx, p, map[string]any{
		"operation":   OpVerifyBlob,
		"content":     content,
		"key":         pubPath,
		"signature":   signData["signature"],
		"ignore_tlog": true,
	})
	assert.Equal(t, true, data["verified"])
	assert.Equal(t, blobDigest([]byte(content)), data["digest"])

	// Nothing named verify-blob-* remains from the temp files.
	entries, err := os.ReadDir(os.TempDir())
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "verify-blob-", "temp blob files must be removed")
	}
}
