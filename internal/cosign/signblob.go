package cosign

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	rekocli "github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	// BundleFormatLegacy writes cosign's JSON bundle (LocalSignedPayload),
	// the same shape `cosign sign-blob --bundle` produces.
	BundleFormatLegacy = "legacy"
	// BundleFormatSigstore writes the sigstore protobuf bundle
	// (`cosign sign-blob --new-bundle-format`, media type
	// application/vnd.dev.sigstore.bundle.v0.3+json).
	BundleFormatSigstore = "sigstore"
)

// signBlobConfig holds the resolved, validated inputs of the sign-blob
// operation: the blob source (exactly one of path or content), the optional
// output files, and the shared signing identity.
type signBlobConfig struct {
	signIdentity
	path              string
	content           string
	outputSignature   string
	outputCertificate string
	bundlePath        string
	bundleFormat      string
}

// executeSignBlob signs a plain blob (a checksum file, a tarball, any bytes)
// and writes a detached signature, mirroring `cosign sign-blob` in-process:
// no cosign binary, no OCI registry. The signature is written to
// output_signature when given and always included (base64) in the output
// data, so resolver-consumed flows can use it without touching the
// filesystem. Optional outputs: the Fulcio certificate (keyless), and a
// bundle in the legacy or sigstore protobuf format.
func (p *Plugin) executeSignBlob(ctx context.Context, input map[string]any) (*sdkprovider.Output, error) {
	cfg, err := parseSignBlobConfig(input)
	if err != nil {
		return nil, err
	}

	sign, err := p.buildSigner(ctx, &cfg.signIdentity)
	if err != nil {
		return nil, err
	}
	defer sign.Close()

	blobHash := sha256.New()
	var blobReader io.Reader
	if cfg.path != "" {
		f, oerr := os.Open(filepath.Clean(cfg.path))
		if oerr != nil {
			return nil, fmt.Errorf("sign-blob: opening blob %q: %w", cfg.path, oerr)
		}
		defer f.Close() //nolint:errcheck // read-only handle
		// Stream the file once through the hasher and the signer; a large
		// blob neither repeats disk reads nor doubles in memory.
		blobReader = io.TeeReader(f, blobHash)
	} else {
		if _, werr := blobHash.Write([]byte(cfg.content)); werr != nil { //nolint:errcheck // sha256 Write never fails
			return nil, werr
		}
		blobReader = strings.NewReader(cfg.content)
	}

	sig, err := sign.sv.SignMessage(blobReader, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("sign-blob: signing blob: %w", err)
	}
	digest := blobHash.Sum(nil)
	digestStr := "sha256:" + hex.EncodeToString(digest)

	var rekorClient *client.Rekor
	if cfg.tlogUpload {
		rekorClient, err = rekocli.NewClient(cfg.rekorURL)
		if err != nil {
			return nil, fmt.Errorf("creating Rekor client for %q: %w", cfg.rekorURL, err)
		}
	}
	var entry *models.LogEntryAnon
	if rekorClient != nil {
		entry, err = p.uploadToRekor(ctx, sign, sig, blobHash, rekorClient)
		if err != nil {
			return nil, fmt.Errorf("uploading to transparency log: %w", err)
		}
	}

	b64Sig := base64.StdEncoding.EncodeToString(sig)

	if cfg.outputSignature != "" {
		if err := os.WriteFile(cfg.outputSignature, []byte(b64Sig), 0600); err != nil {
			return nil, fmt.Errorf("sign-blob: writing signature file %q: %w", cfg.outputSignature, err)
		}
	}
	if cfg.outputCertificate != "" {
		if err := os.WriteFile(cfg.outputCertificate, sign.cert, 0600); err != nil {
			return nil, fmt.Errorf("sign-blob: writing certificate file %q: %w", cfg.outputCertificate, err)
		}
	}
	if cfg.bundlePath != "" {
		if err := p.writeBlobBundle(cfg, sign, sig, digest, entry); err != nil {
			return nil, err
		}
	}

	data := map[string]any{
		"success":   true,
		"digest":    digestStr,
		"signature": b64Sig,
	}
	if cfg.path != "" {
		data["path"] = cfg.path
	}
	if cfg.outputSignature != "" {
		data["signature_path"] = cfg.outputSignature
	}
	if cfg.outputCertificate != "" {
		data["certificate_path"] = cfg.outputCertificate
	}
	if cfg.bundlePath != "" {
		data["bundle_path"] = cfg.bundlePath
		data["bundle_format"] = cfg.bundleFormat
	}
	if sign.cert != nil {
		data["certificate"] = string(sign.cert)
	}
	if entry != nil && entry.LogIndex != nil {
		data["tlog_index"] = *entry.LogIndex
		data["tlog_url"] = tlogEntryURL(cfg.rekorURL, *entry.LogIndex)
	}

	return &sdkprovider.Output{Data: data}, nil
}

// writeBlobBundle writes the detached-signature bundle to the configured
// path in the configured format.
func (p *Plugin) writeBlobBundle(cfg *signBlobConfig, sign *signer, sig, digest []byte, entry *models.LogEntryAnon) error {
	var contents []byte
	var err error
	if cfg.bundleFormat == BundleFormatSigstore {
		bundle, berr := p.buildSigstoreBundle(sign, sig, digest, entry)
		if berr != nil {
			return berr
		}
		contents, err = protojson.Marshal(bundle)
		if err != nil {
			return fmt.Errorf("sign-blob: marshaling sigstore bundle: %w", err)
		}
	} else {
		lsp := pkgcosign.LocalSignedPayload{Base64Signature: base64.StdEncoding.EncodeToString(sig)}
		if sign.cert != nil {
			lsp.Cert = base64.StdEncoding.EncodeToString(sign.cert)
		}
		if entry != nil {
			lsp.Bundle = cbundle.EntryToBundle(entry)
		}
		contents, err = json.Marshal(lsp)
		if err != nil {
			return fmt.Errorf("sign-blob: marshaling legacy bundle: %w", err)
		}
	}
	if err := os.WriteFile(cfg.bundlePath, contents, 0600); err != nil {
		return fmt.Errorf("sign-blob: writing bundle file %q: %w", cfg.bundlePath, err)
	}
	return nil
}

// buildSigstoreBundle assembles the sigstore protobuf bundle exactly as
// cosign's sign-blob --new-bundle-format does: the Fulcio certificate
// (keyless) or a SHA-256 hint of the public key (key-based) as verification
// material, and the message signature with the blob digest.
func (p *Plugin) buildSigstoreBundle(sign *signer, sig, digest []byte, entry *models.LogEntryAnon) (*protobundle.Bundle, error) {
	var hint string
	var rawCert []byte

	if sign.cert != nil {
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(sign.cert)
		if err != nil {
			return nil, fmt.Errorf("parsing signing certificate: %w", err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("signing certificate is empty")
		}
		rawCert = certs[0].Raw
	} else {
		pub, err := sign.sv.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("getting public key: %w", err)
		}
		pkixPub, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("marshaling public key: %w", err)
		}
		hashed := sha256.Sum256(pkixPub)
		hint = base64.StdEncoding.EncodeToString(hashed[:])
	}

	bundle, err := cbundle.MakeProtobufBundle(hint, rawCert, entry, nil)
	if err != nil {
		return nil, fmt.Errorf("building sigstore bundle: %w", err)
	}
	bundle.Content = &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    digest,
			},
			Signature: sig,
		},
	}
	return bundle, nil
}

// parseSignBlobConfig resolves and validates the sign-blob inputs. It
// performs no I/O so validation errors are deterministic.
func parseSignBlobConfig(input map[string]any) (*signBlobConfig, error) {
	cfg := &signBlobConfig{}

	path, _ := input["path"].(string)
	content, _ := input["content"].(string)
	switch {
	case path != "" && content != "":
		return nil, fmt.Errorf("set only one of path or content, not both")
	case path == "" && content == "":
		return nil, fmt.Errorf(`required fields "path" (file) or "content" (inline) are missing: set exactly one`)
	}
	cfg.path, cfg.content = path, content

	cfg.outputSignature, _ = input["output_signature"].(string)
	cfg.outputCertificate, _ = input["output_certificate"].(string)
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
	if cfg.bundleFormat != BundleFormatLegacy && cfg.bundlePath == "" {
		return nil, fmt.Errorf("bundle_format %s requires the bundle output path to be set", cfg.bundleFormat)
	}

	id, err := parseSignIdentity(input)
	if err != nil {
		return nil, err
	}
	cfg.signIdentity = *id

	if cfg.outputCertificate != "" && !id.keyless {
		return nil, fmt.Errorf("output_certificate requires keyless signing: key-based and KMS signatures carry no certificate")
	}
	return cfg, nil
}
