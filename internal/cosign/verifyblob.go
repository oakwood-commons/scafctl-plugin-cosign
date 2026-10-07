package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	fulciocli "github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	rekocli "github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgroot "github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// verifyBlobConfig holds the resolved, validated inputs of the verify-blob
// operation: the blob source (exactly one of path or content), the
// signature source, and the trust anchors to verify against.
type verifyBlobConfig struct {
	path               string
	content            string
	signature          string
	signaturePath      string
	bundlePath         string
	bundleFormat       string
	key                string
	certificate        string
	certIdentity       string
	certIdentityRegexp string
	certIssuer         string
	certIssuerRegexp   string
	caRoots            string
	caIntermediates    string
	certChain          string
	trustedRoot        string
	rekorURL           string
	ignoreTlog         bool
}

// executeVerifyBlob checks a detached blob signature in-process, mirroring
// `cosign verify-blob` (pin-and-assert): against a public key reference, or
// keyless against a certificate and a pinned identity/issuer pair, with an
// optional legacy or sigstore-format bundle. A failed verification returns
// an error, so a failed assert stops the pipeline.
//
// The verification core is cosign's own: VerifyBlobSignature for the legacy
// path and VerifyNewBundle for the sigstore bundle format — the same code
// `cosign verify-blob` runs. The production import stays on the pkg-level
// APIs; the heavier cli/verify package is linked only from tests.
func (p *Plugin) executeVerifyBlob(ctx context.Context, input map[string]any) (*sdkprovider.Output, error) {
	cfg, err := parseVerifyBlobConfig(input)
	if err != nil {
		return nil, err
	}

	blobPath := cfg.path
	if cfg.content != "" {
		blobPath, err = writeTempBlob(cfg.content)
		if err != nil {
			return nil, err
		}
		defer os.Remove(blobPath) //nolint:errcheck // best-effort temp cleanup
	}

	blobBytes, err := os.ReadFile(blobPath) //nolint:gosec // user-provided blob path, like cosign verify-blob
	if err != nil {
		return nil, fmt.Errorf("verify-blob: reading blob %q: %w", blobPath, err)
	}
	digest := sha256.Sum256(blobBytes)

	co := &pkgcosign.CheckOpts{
		IgnoreTlog:      cfg.ignoreTlog,
		NewBundleFormat: cfg.bundleFormat == BundleFormatSigstore,
	}
	// Identities only apply to keyless verification; with a key they would
	// make VerifyNewBundle require a certificate identity (mirrors stock).
	if cfg.key == "" {
		co.Identities = cfg.identities()
	}

	if co.TrustedMaterial, err = loadTrustedMaterial(cfg); err != nil {
		return nil, err
	}

	// Keys and certificates are mutually exclusive verifiers.
	var cert *x509.Certificate
	switch {
	case cfg.key != "":
		co.SigVerifier, err = sigs.PublicKeyFromKeyRefWithHashAlgo(ctx, cfg.key, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("verify-blob: loading public key %q: %w", cfg.key, err)
		}
	case cfg.certificate != "":
		cert, err = loadCertFromFile(cfg.certificate)
		if err != nil {
			return nil, fmt.Errorf("verify-blob: loading certificate %q: %w", cfg.certificate, err)
		}
	}

	if co.TrustedMaterial == nil && !cfg.ignoreTlog {
		if cfg.rekorURL != "" {
			rekorClient, cerr := rekocli.NewClient(cfg.rekorURL)
			if cerr != nil {
				return nil, fmt.Errorf("verify-blob: creating Rekor client for %q: %w", cfg.rekorURL, cerr)
			}
			co.RekorClient = rekorClient
		}
		// Needed to verify tlog entries, both online and offline. Fetched
		// through the sigstore TUF client (network; cached under ~/.sigstore).
		co.RekorPubKeys, err = pkgcosign.GetRekorPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("verify-blob: getting Rekor public keys: %w", err)
		}
	}

	bundleVerified := false
	if co.NewBundleFormat {
		bundleVerified, err = p.verifyBlobBundle(ctx, co, blobBytes, cfg)
	} else {
		// Trust anchors (Fulcio roots, CT log keys) apply to keyless
		// verification only: a certificate, or a bundle carrying one —
		// exactly cosign's keylessVerification gate.
		if cfg.key == "" {
			if err = setLegacyVerifyTrust(ctx, co, cfg); err != nil {
				return nil, err
			}
		}
		bundleVerified, err = p.verifyBlobLegacy(ctx, co, blobBytes, cfg, cert)
	}
	if err != nil {
		return nil, fmt.Errorf("verify-blob: %w", err)
	}

	data := map[string]any{
		"success":         true,
		"verified":        true,
		"digest":          "sha256:" + hex.EncodeToString(digest[:]),
		"bundle_verified": bundleVerified,
	}
	if cfg.path != "" {
		data["path"] = cfg.path
	}
	return &sdkprovider.Output{Data: data}, nil
}

// verifyBlobLegacy runs the legacy (or signature-only) verification path:
// assemble the static signature with its certificate/bundle, and hand it to
// cosign's VerifyBlobSignature.
func (p *Plugin) verifyBlobLegacy(ctx context.Context, co *pkgcosign.CheckOpts, blobBytes []byte, cfg *verifyBlobConfig, cert *x509.Certificate) (bool, error) {
	b64sig, bundleCert, rekorBundle, err := loadSignatureAndLegacyBundle(cfg)
	if err != nil {
		return false, err
	}
	if bundleCert != nil {
		// If a certificate was passed in, it must match the bundle's.
		if cert != nil && !cert.Equal(bundleCert) {
			return false, errors.New("the certificate passed in does not match the certificate in the provided bundle")
		}
		cert = bundleCert
	}
	if co.SigVerifier == nil && cert == nil {
		return false, errors.New("bundle does not contain a certificate for verification; provide a public key")
	}

	opts := []static.Option{}
	if cert != nil {
		certPEM, cerr := cryptoutils.MarshalCertificateToPEM(cert)
		if cerr != nil {
			return false, fmt.Errorf("marshaling certificate: %w", cerr)
		}
		opts = append(opts, static.WithCertChain(certPEM, nil))
	}
	if rekorBundle != nil {
		opts = append(opts, static.WithBundle(rekorBundle))
	}

	sig, err := static.NewSignature(blobBytes, b64sig, opts...)
	if err != nil {
		return false, fmt.Errorf("creating signature object: %w", err)
	}
	return pkgcosign.VerifyBlobSignature(ctx, sig, co)
}

// verifyBlobBundle runs the sigstore protobuf-bundle verification path
// (cosign's --new-bundle-format): the bundle plus a trusted root go through
// cosign's VerifyNewBundle.
func (p *Plugin) verifyBlobBundle(ctx context.Context, co *pkgcosign.CheckOpts, blobBytes []byte, cfg *verifyBlobConfig) (bool, error) {
	if cfg.bundlePath == "" {
		return false, errors.New("bundle is required when bundle_format is sigstore")
	}
	b, err := sgbundle.LoadJSONFromPath(cfg.bundlePath)
	if err != nil {
		return false, fmt.Errorf("loading sigstore bundle %q: %w", cfg.bundlePath, err)
	}
	_, err = pkgcosign.VerifyNewBundle(ctx, co, sgverify.WithArtifact(bytes.NewReader(blobBytes)), b)
	if err != nil {
		return false, err
	}
	// VerifyNewBundle returns a result when verification succeeded: the
	// signature, and the tlog entry when the trusted root requires one.
	return true, nil
}

// setLegacyVerifyTrust assembles the certificate-trust fields for keyless
// verification: explicit PEM pools from ca_roots/ca_intermediates or
// certificate_chain when given, the sigstore TUF client's Fulcio roots and
// CT log keys otherwise (mirror of cosign's loadCertsKeylessVerification and
// shouldVerifySCT wiring). Never called for key-based verification.
func setLegacyVerifyTrust(ctx context.Context, co *pkgcosign.CheckOpts, cfg *verifyBlobConfig) error {
	var err error
	switch {
	case cfg.certChain != "":
		chain, err := loadCertChainFromFile(cfg.certChain)
		if err != nil {
			return fmt.Errorf("verify-blob: loading certificate_chain: %w", err)
		}
		if len(chain) == 0 {
			return errors.New("verify-blob: expected certificates in certificate_chain")
		}
		co.RootCerts = x509.NewCertPool()
		co.RootCerts.AddCert(chain[len(chain)-1])
		if len(chain) > 1 {
			co.IntermediateCerts = x509.NewCertPool()
			for _, c := range chain[:len(chain)-1] {
				co.IntermediateCerts.AddCert(c)
			}
		}
	case cfg.caRoots != "":
		roots, err := loadCertChainFromFile(cfg.caRoots)
		if err != nil {
			return fmt.Errorf("verify-blob: loading ca_roots: %w", err)
		}
		co.RootCerts = x509.NewCertPool()
		for _, c := range roots {
			co.RootCerts.AddCert(c)
		}
		if cfg.caIntermediates != "" {
			inters, err := loadCertChainFromFile(cfg.caIntermediates)
			if err != nil {
				return fmt.Errorf("verify-blob: loading ca_intermediates: %w", err)
			}
			co.IntermediateCerts = x509.NewCertPool()
			for _, c := range inters {
				co.IntermediateCerts.AddCert(c)
			}
		}
	default:
		// Online fetch of the Fulcio roots and intermediates through the
		// sigstore TUF client: keyless certificates (Ed25519-signed by
		// Fulcio) cannot be verified without a trust anchor, and none was
		// given. Mirrors `cosign verify-blob`'s own default branch; cached
		// under ~/.sigstore / ~/.cache/sigstore after the first fetch.
		co.RootCerts, err = fulciocli.GetRoots()
		if err != nil {
			return fmt.Errorf("verify-blob: getting Fulcio roots (pass ca_roots or certificate_chain for private deployments): %w", err)
		}
		co.IntermediateCerts, err = fulciocli.GetIntermediates()
		if err != nil {
			return fmt.Errorf("verify-blob: getting Fulcio intermediates: %w", err)
		}
	}

	// CT log keys for the embedded-SCT check on keyless certificates, via
	// the same TUF client.
	co.CTLogPubKeys, err = pkgcosign.GetCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("verify-blob: getting CT log public keys: %w", err)
	}
	return nil
}

// identities converts the pinned identity inputs to cosign Identity. The
// guard runs in parseVerifyBlobConfig, so the pair is present by here.
func (cfg *verifyBlobConfig) identities() []pkgcosign.Identity {
	return []pkgcosign.Identity{{
		Issuer:        cfg.certIssuer,
		IssuerRegExp:  cfg.certIssuerRegexp,
		Subject:       cfg.certIdentity,
		SubjectRegExp: cfg.certIdentityRegexp,
	}}
}

// loadSignatureAndLegacyBundle resolves the base64 signature (inline, from a
// file, or from a legacy bundle) and, when a legacy bundle is given, its
// certificate and Rekor bundle.
func loadSignatureAndLegacyBundle(cfg *verifyBlobConfig) (string, *x509.Certificate, *cbundle.RekorBundle, error) {
	var b64sig string

	switch {
	case cfg.signature != "":
		if _, err := base64.StdEncoding.DecodeString(cfg.signature); err != nil {
			return "", nil, nil, fmt.Errorf("signature must be base64-encoded")
		}
		b64sig = cfg.signature
	case cfg.signaturePath != "":
		raw, err := os.ReadFile(cfg.signaturePath) //nolint:gosec // user-provided signature file
		if err != nil {
			return "", nil, nil, fmt.Errorf("reading signature file %q: %w", cfg.signaturePath, err)
		}
		if isBase64(raw) {
			b64sig = string(raw)
		} else {
			b64sig = base64.StdEncoding.EncodeToString(raw)
		}
	}

	var cert *x509.Certificate
	var bundle *cbundle.RekorBundle
	if cfg.bundlePath != "" {
		lsp, err := pkgcosign.FetchLocalSignedPayloadFromPath(cfg.bundlePath)
		if err != nil {
			return "", nil, nil, fmt.Errorf("loading bundle %q: %w", cfg.bundlePath, err)
		}
		if lsp.Cert != "" {
			certBytes := []byte(lsp.Cert)
			if isBase64(certBytes) {
				certBytes, _ = base64.StdEncoding.DecodeString(lsp.Cert)
			}
			cert, err = certFromPEM(certBytes)
			if err != nil {
				return "", nil, nil, fmt.Errorf("loading certificate from bundle: %w", err)
			}
		}
		if b64sig == "" {
			if lsp.Base64Signature == "" {
				return "", nil, nil, fmt.Errorf("bundle %q carries no signature and none was provided", cfg.bundlePath)
			}
			b64sig = lsp.Base64Signature
		}
		if lsp.Bundle != nil {
			bundle = lsp.Bundle
		}
	}

	if b64sig == "" {
		return "", nil, nil, fmt.Errorf(`required field "signature", "signature_path", or "bundle" is missing`)
	}
	return b64sig, cert, bundle, nil
}

// loadTrustedMaterial loads the sigstore trusted root from trusted_root for
// the sigstore bundle path; it is nil on the legacy path.
func loadTrustedMaterial(cfg *verifyBlobConfig) (sgroot.TrustedMaterial, error) {
	if cfg.trustedRoot == "" {
		return nil, nil
	}
	tm, err := sgroot.NewTrustedRootFromPath(cfg.trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("verify-blob: loading trusted root %q: %w", cfg.trustedRoot, err)
	}
	return tm, nil
}

// writeTempBlob writes inline blob content to a temp file and returns its
// path (the verification path works on files, matching cosign's blobRef).
func writeTempBlob(content string) (string, error) {
	f, err := os.CreateTemp("", "verify-blob-*.bin")
	if err != nil {
		return "", fmt.Errorf("verify-blob: creating temporary blob file: %w", err)
	}
	name := f.Name()
	if _, werr := f.WriteString(content); werr != nil {
		f.Close()       //nolint:gosec,errcheck // best-effort cleanup on error path
		os.Remove(name) //nolint:gosec,errcheck // best-effort cleanup on error path
		return "", fmt.Errorf("verify-blob: writing temporary blob file: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		os.Remove(name) //nolint:gosec,errcheck // best-effort cleanup on error path
		return "", fmt.Errorf("verify-blob: closing temporary blob file: %w", cerr)
	}
	return name, nil
}

// parseVerifyBlobConfig resolves and validates the verify-blob inputs. It
// performs no I/O so validation errors are deterministic.
func parseVerifyBlobConfig(input map[string]any) (*verifyBlobConfig, error) {
	cfg := &verifyBlobConfig{}

	path, _ := input["path"].(string)
	content, _ := input["content"].(string)
	switch {
	case path != "" && content != "":
		return nil, fmt.Errorf("set only one of path or content, not both")
	case path == "" && content == "":
		return nil, fmt.Errorf(`required fields "path" (file) or "content" (inline) are missing: set exactly one`)
	}
	cfg.path, cfg.content = path, content

	cfg.signature, _ = input["signature"].(string)
	cfg.signaturePath, _ = input["signature_path"].(string)
	if cfg.signature != "" && cfg.signaturePath != "" {
		return nil, fmt.Errorf("set only one of signature or signature_path, not both")
	}
	cfg.bundlePath, _ = input["bundle"].(string)

	format, _ := input["bundle_format"].(string)
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", BundleFormatLegacy:
		cfg.bundleFormat = BundleFormatLegacy
	case BundleFormatSigstore:
		cfg.bundleFormat = BundleFormatSigstore
	default:
		return nil, fmt.Errorf("invalid bundle_format %q: expected %q or %q", format, BundleFormatLegacy, BundleFormatSigstore)
	}

	cfg.key, _ = input["key"].(string)
	if err := validateKeyRef(cfg.key); err != nil {
		return nil, err
	}
	cfg.certificate, _ = input["certificate"].(string)
	cfg.certIdentity, _ = input["certificate_identity"].(string)
	cfg.certIdentityRegexp, _ = input["certificate_identity_regexp"].(string)
	cfg.certIssuer, _ = input["certificate_oidc_issuer"].(string)
	cfg.certIssuerRegexp, _ = input["certificate_oidc_issuer_regexp"].(string)
	cfg.caRoots, _ = input["ca_roots"].(string)
	cfg.caIntermediates, _ = input["ca_intermediates"].(string)
	cfg.certChain, _ = input["certificate_chain"].(string)
	cfg.trustedRoot, _ = input["trusted_root"].(string)
	cfg.rekorURL, _ = input["rekor_url"].(string)

	if raw, ok := input["ignore_tlog"]; ok {
		b, err := toBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ignore_tlog: %w", err)
		}
		cfg.ignoreTlog = b
	}

	if cfg.bundleFormat == BundleFormatSigstore {
		if cfg.bundlePath == "" {
			return nil, fmt.Errorf("bundle is required when bundle_format is sigstore")
		}
		if cfg.trustedRoot == "" {
			return nil, fmt.Errorf("trusted_root is required when bundle_format is sigstore (no endpoint is fetched implicitly)")
		}
	}
	if cfg.bundleFormat != BundleFormatSigstore && cfg.trustedRoot != "" {
		return nil, fmt.Errorf("trusted_root is only supported with bundle_format %s", BundleFormatSigstore)
	}

	// A verifier is required: key, certificate, or bundle.
	if cfg.key == "" && cfg.certificate == "" && cfg.bundlePath == "" {
		return nil, fmt.Errorf("provide a key, a certificate to verify against, or a bundle")
	}
	if cfg.key != "" && cfg.certificate != "" {
		return nil, fmt.Errorf("set only one of key or certificate, not both")
	}
	if cfg.key != "" && (cfg.certIdentity != "" || cfg.certIdentityRegexp != "" || cfg.certIssuer != "" || cfg.certIssuerRegexp != "") {
		return nil, fmt.Errorf("certificate_identity/certificate_oidc_issuer apply to certificate or bundle verification only, not to a key")
	}

	// Keyless verification (certificate, or a bundle carrying one) requires
	// a pinned identity and issuer, exactly like cosign.
	if cfg.key == "" {
		if cfg.certIdentity == "" && cfg.certIdentityRegexp == "" {
			return nil, fmt.Errorf("certificate_identity or certificate_identity_regexp is required for keyless verification")
		}
		if cfg.certIssuer == "" && cfg.certIssuerRegexp == "" {
			return nil, fmt.Errorf("certificate_oidc_issuer or certificate_oidc_issuer_regexp is required for keyless verification")
		}
	}
	if err := validateKeyRef(cfg.certificate); err != nil {
		// certificate is a file path or URL, never a KMS ref, but the same
		// scheme guard applies for consistency.
		return nil, err
	}

	return cfg, nil
}

// isBase64 reports whether data decodes cleanly as standard base64.
func isBase64(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

// certFromPEM parses one certificate out of PEM (or raw-base64 PEM) bytes.
func certFromPEM(pems []byte) (*x509.Certificate, error) {
	out, err := base64.StdEncoding.DecodeString(string(pems))
	if err == nil {
		pems = out
	}
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pems)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in pem")
	}
	return certs[0], nil
}

// loadCertFromFile reads a certificate from a file path (PEM, possibly
// base64-wrapped, like cosign's --certificate).
func loadCertFromFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // user-provided certificate file
	if err != nil {
		return nil, err
	}
	return certFromPEM(raw)
}

// loadCertChainFromFile reads a PEM certificate chain from a file path.
func loadCertChainFromFile(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // user-provided chain file
	if err != nil {
		return nil, err
	}
	return cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(raw))
}
