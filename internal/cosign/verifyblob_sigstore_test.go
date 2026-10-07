package cosign

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyBlob_BundleSigstore_KeyBased proves the offline protobuf-bundle
// verification path end to end: sign-blob writes a sigstore-format bundle
// (key-based, no tlog entry), and verify-blob checks it against the public
// key with a trusted root built from sigstore-go's virtual instance — no
// network, no live sigstore.
func TestVerifyBlob_BundleSigstore_KeyBased(t *testing.T) {
	key := writeTestKey(t)
	ctx := context.Background()
	blob := "artifact for the protobuf bundle path\n"
	blobPath := writeBlobFile(t, "artifact.bin", blob)
	bundlePath := filepath.Join(t.TempDir(), "artifact.sigstore.bundle")
	pubPath := writeBlobFile(t, "cosign.pub", string(key.pubPEM))
	p := &Plugin{}

	signBlob(t, ctx, p, map[string]any{
		"path":          blobPath,
		"key":           key.path,
		"bundle":        bundlePath,
		"bundle_format": BundleFormatSigstore,
	})

	// A trusted root from the virtual sigstore provides the certificate
	// authorities and transparency logs the format needs to carry; key-based
	// verification with ignore_tlog does not consult them, but a trusted
	// root is required on this path by design (as with cosign).
	trustedRootPath := writeVirtualTrustedRoot(t)

	data := sign(t, ctx, p, map[string]any{
		"operation":     OpVerifyBlob,
		"path":          blobPath,
		"key":           pubPath,
		"bundle":        bundlePath,
		"bundle_format": BundleFormatSigstore,
		"trusted_root":  trustedRootPath,
		"ignore_tlog":   true,
	})
	assert.Equal(t, true, data["verified"])

	// A tampered blob against the same bundle must fail.
	tampered := writeBlobFile(t, "artifact.bin", "artifact for the protobuf bundle path, tampered\n")
	_, err := p.ExecuteProvider(ctx, ProviderName, map[string]any{
		"operation":     OpVerifyBlob,
		"path":          tampered,
		"key":           pubPath,
		"bundle":        bundlePath,
		"bundle_format": BundleFormatSigstore,
		"trusted_root":  trustedRootPath,
		"ignore_tlog":   true,
	})
	require.Error(t, err, "a tampered blob must fail sigstore-bundle verification")
}

// writeVirtualTrustedRoot builds a trusted root from sigstore-go's virtual
// sigstore and returns the path of its JSON serialization.
func writeVirtualTrustedRoot(t *testing.T) string {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)
	tr, err := sgroot.NewTrustedRoot(
		sgroot.TrustedRootMediaType01,
		vs.FulcioCertificateAuthorities(),
		vs.CTLogs(),
		vs.TimestampingAuthorities(),
		vs.RekorLogs(),
	)
	require.NoError(t, err)
	trJSON, err := tr.MarshalJSON()
	require.NoError(t, err)
	return writeBlobFile(t, "trusted_root.json", string(trJSON))
}

// TestVerifyBlob_Keyless_AmbientToken exercises keyless verify end to end
// against live sigstore: keyless sign-blob produces a certificate, and
// verify-blob pins the identity and issuer read from that certificate, with
// the transparency log checked. Env-gated like the keyless sign tests.
func TestVerifyBlob_Keyless_AmbientToken(t *testing.T) {
	fulcioURL := os.Getenv("COSIGN_TEST_FULCIO_URL")
	rekorURL := os.Getenv("COSIGN_TEST_REKOR_URL")
	if fulcioURL == "" || rekorURL == "" {
		t.Skip("set COSIGN_TEST_FULCIO_URL and COSIGN_TEST_REKOR_URL to run the keyless verify integration test")
	}

	blob := "assert me before publishing\n"
	blobPath := writeBlobFile(t, "release.bin", blob)
	sigPath := filepath.Join(t.TempDir(), "release.bin.sig")
	certPath := filepath.Join(t.TempDir(), "release.bin.cert.pem")
	p := &Plugin{}
	ctx := context.Background()

	t.Setenv("SIGSTORE_ID_TOKEN", os.Getenv("COSIGN_TEST_ID_TOKEN"))
	skipFulcioVerify := os.Getenv("COSIGN_TEST_SKIP_FULCIO_VERIFY") == "true"

	signBlob(t, ctx, p, map[string]any{
		"path":                        blobPath,
		"fulcio_url":                  fulcioURL,
		"rekor_url":                   rekorURL,
		"output_signature":            sigPath,
		"output_certificate":          certPath,
		"fulcio_insecure_skip_verify": skipFulcioVerify,
	})

	// Read the identity and issuer the certificate actually carries, so the
	// pinned pair matches exactly what this Fulcio issued.
	cert, err := loadCertFromFile(certPath)
	require.NoError(t, err)
	exts, err := certificate.ParseExtensions(cert.Extensions)
	require.NoError(t, err)
	require.NotEmpty(t, exts.Issuer, "Fulcio certificate carries the OIDC issuer extension")

	identity := identityFromCert(t, cert)

	data := sign(t, ctx, p, map[string]any{
		"operation":               OpVerifyBlob,
		"path":                    blobPath,
		"certificate":             certPath,
		"certificate_identity":    identity,
		"certificate_oidc_issuer": exts.Issuer,
		"signature_path":          sigPath,
		"rekor_url":               rekorURL,
	})
	assert.Equal(t, true, data["verified"])
}

// identityFromCert picks the SAN identity from a Fulcio-issued certificate.
func identityFromCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	switch {
	case len(cert.URIs) > 0:
		return cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		return cert.EmailAddresses[0]
	case len(cert.DNSNames) > 0:
		return cert.DNSNames[0]
	default:
		t.Fatal("certificate carries no usable SAN identity")
		return ""
	}
}

// TestSetLegacyVerifyTrust_PoolConstruction covers the explicit trust-anchor
// branches offline: ca_roots + ca_intermediates and certificate_chain each
// build the expected root and intermediate pools.
func TestSetLegacyVerifyTrust_PoolConstruction(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)

	fulcioCA, ok := vs.FulcioCertificateAuthorities()[0].(*sgroot.FulcioCertificateAuthority)
	require.True(t, ok, "virtual sigstore exposes a FulcioCertificateAuthority")
	root := fulcioCA.Root
	require.NotEmpty(t, fulcioCA.Intermediates)

	chainPEM := filepath.Join(t.TempDir(), "chain.pem")
	rootPEM := filepath.Join(t.TempDir(), "roots.pem")
	interPEM := filepath.Join(t.TempDir(), "inters.pem")

	// certificate_chain: parent intermediate through root (last = trusted
	// root); ca_roots: the root alone; ca_intermediates: the intermediate.
	chainBytes, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{fulcioCA.Intermediates[0], root})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(chainPEM, chainBytes, 0600))
	rootBytes, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{root})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(rootPEM, rootBytes, 0600))
	interBytes, err := cryptoutils.MarshalCertificatesToPEM(fulcioCA.Intermediates)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(interPEM, interBytes, 0600))

	tests := []struct {
		name       string
		cfg        verifyBlobConfig
		wantRoot   *x509.Certificate
		wantInters []*x509.Certificate
	}{
		{name: "ca_roots only", cfg: verifyBlobConfig{caRoots: rootPEM}, wantRoot: root},
		{name: "ca_roots plus intermediates", cfg: verifyBlobConfig{caRoots: rootPEM, caIntermediates: interPEM}, wantRoot: root, wantInters: fulcioCA.Intermediates},
		{name: "certificate_chain", cfg: verifyBlobConfig{certChain: chainPEM}, wantRoot: root, wantInters: fulcioCA.Intermediates[:1]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			co := &pkgcosign.CheckOpts{}
			require.NoError(t, setLegacyVerifyTrust(context.Background(), co, &tt.cfg))

			wantRootPool := x509.NewCertPool()
			wantRootPool.AddCert(tt.wantRoot)
			require.NotNil(t, co.RootCerts)
			assert.True(t, co.RootCerts.Equal(wantRootPool), "unexpected root pool contents")

			if tt.wantInters == nil {
				assert.Nil(t, co.IntermediateCerts)
				return
			}
			wantInterPool := x509.NewCertPool()
			for _, c := range tt.wantInters {
				wantInterPool.AddCert(c)
			}
			require.NotNil(t, co.IntermediateCerts)
			assert.True(t, co.IntermediateCerts.Equal(wantInterPool), "unexpected intermediate pool contents")
		})
	}
}
