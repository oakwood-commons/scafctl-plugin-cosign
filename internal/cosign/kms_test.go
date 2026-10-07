package cosign

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateKeyRef locks the key-reference guard: every scheme that would
// fall through to sigstore's external cliplugin (which execs a
// sigstore-kms-<scheme> binary) is rejected before any key loading starts,
// and every in-process reference is accepted.
func TestValidateKeyRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		keyRef  string
		wantErr string
	}{
		{name: "empty is optional", keyRef: ""},
		{name: "plain relative path", keyRef: "./cosign.key"},
		{name: "plain absolute path", keyRef: "/secrets/cosign.key"},
		{name: "env reference", keyRef: "env://COSIGN_KEY"},
		{name: "k8s secret", keyRef: "k8s://cosign-system/cosign-key"},
		{name: "https key URL", keyRef: "https://keys.example.com/cosign.pub"},
		{name: "http key URL", keyRef: "http://keys.example.com/cosign.pub"},
		{name: "gcp kms", keyRef: "gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k"},
		{name: "aws kms", keyRef: "awskms://alias/my-key"},
		{name: "azure kms", keyRef: "azurekms:///my-vault/my-key"},
		{name: "hashivault kms", keyRef: "hashivault://my-vault/my-key"},
		{
			name:    "unknown scheme would exec a plugin binary",
			keyRef:  "mykms://my-key",
			wantErr: `unsupported key scheme "mykms"`,
		},
		{
			name:    "typo in gcpkms scheme",
			keyRef:  "gcpkm://my-key",
			wantErr: `unsupported key scheme "gcpkm"`,
		},
		{
			name:    "pkcs11 hardware tokens unsupported",
			keyRef:  "pkcs11:token=my-token",
			wantErr: "hardware token (pkcs11) keys are not supported",
		},
		{
			name:    "gitlab scheme unsupported",
			keyRef:  "gitlab://my-group/my-project",
			wantErr: `unsupported key scheme "gitlab"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateKeyRef(tt.keyRef)
			if tt.wantErr == "" {
				require.NoError(t, err, "key ref %q must pass the guard", tt.keyRef)
				return
			}
			require.Error(t, err, "key ref %q must be rejected", tt.keyRef)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestKMSBackendsLinked proves the blank imports in kms.go actually
// registered the four sigstore KMS backends: without them these schemes fall
// through to the external cliplugin.
func TestKMSBackendsLinked(t *testing.T) {
	t.Parallel()
	providers := supportedKeySchemes()
	for _, scheme := range []string{"gcpkms://", "awskms://", "azurekms://", "hashivault://"} {
		assert.Contains(t, providers, scheme, "KMS backend %s must be registered", scheme)
	}
}
