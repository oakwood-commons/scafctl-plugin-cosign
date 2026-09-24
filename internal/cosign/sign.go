package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio/fulcioverifier"
	cosignopts "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	rekocli "github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	pkgcosign "github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	cremote "github.com/sigstore/cosign/v2/pkg/cosign/remote"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/oci/walk"
	sigs "github.com/sigstore/cosign/v2/pkg/signature"

	// Registers the ambient OIDC providers (SIGSTORE_ID_TOKEN, GitHub
	// Actions, SPIFFE, ...) consulted for keyless signing.
	_ "github.com/sigstore/cosign/v2/pkg/providers/all"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

const (
	// ReferrersModeOCI11 stores signatures as OCI 1.1 referrer artifacts.
	ReferrersModeOCI11 = "oci-1-1"
	// ReferrersModeLegacy stores signatures under sha256-<digest>.sig tags.
	ReferrersModeLegacy = "legacy"

	// cosignSignatureArtifactType is the artifactType cosign writes on
	// signature referrer manifests in OCI 1.1 mode.
	cosignSignatureArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
)

// signConfig holds the resolved, validated inputs of the sign operation.
type signConfig struct {
	ref              string
	key              string
	keyless          bool
	oidcHandler      string
	fulcioURL        string
	rekorURL         string
	tlogUpload       bool
	skipFulcioVerify bool
	referrersMode    string
	annotations      map[string]string
	recursive        bool
}

// signer carries the signing identity for one executeSign call.
// For keyless signing, cert and chain hold the Fulcio-issued certificate.
type signer struct {
	sv    signature.SignerVerifier
	cert  []byte
	chain []byte
}

// Close releases any hardware-backed key handles.
func (s *signer) Close() {
	if c, ok := s.sv.(interface{ Close() }); ok {
		c.Close()
	}
}

// signResult captures what one signature write produced.
type signResult struct {
	digest          string // digest of the signed subject
	signatureDigest string // digest of the signature artifact
	payloadDigest   string // digest of the signed payload blob
	tlogIndex       int64
	tlogSet         bool
}

// passFunc supplies the password for encrypted cosign keys from the
// COSIGN_PASSWORD environment variable. It never prompts: the plugin runs
// non-interactively, so an unset password surfaces as a key-decryption
// error rather than a hanging prompt.
func passFunc(bool) ([]byte, error) {
	return []byte(os.Getenv("COSIGN_PASSWORD")), nil
}

// executeSign signs the artifact referenced by ref and attaches the
// signature to the registry, mirroring `cosign sign` in-process.
//
// No cosign binary is invoked; everything runs through the embedded
// sigstore libraries (the AC #3 no-shell guarantee).
func (p *Plugin) executeSign(ctx context.Context, input map[string]any) (*sdkprovider.Output, error) {
	cfg, err := parseSignConfig(input)
	if err != nil {
		return nil, err
	}

	retryOpts, err := parseRetry(input)
	if err != nil {
		return nil, err
	}

	ref, err := p.parseReference(cfg.ref)
	if err != nil {
		return nil, err
	}

	opts := p.remoteOptions(ctx, retryOpts...)

	// Build the signer before touching the registry so a bad key or missing
	// identity fails fast, without network side effects first.
	sign, err := p.buildSigner(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer sign.Close()

	// Resolve the subject up front: a tag ref is resolved to its digest
	// here, and the digest is what gets signed.
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, mapRegistryError(fmt.Sprintf("sign: resolving %q to a digest", cfg.ref), err)
	}

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(opts...)}
	if p.insecure {
		ociOpts = append(ociOpts, ociremote.WithNameOptions(name.Insecure))
	}

	// Fetching the real entity (not a digest-only stub) lets the dupe
	// detector see existing signatures, so re-signing with the same key
	// does not stack duplicate entries.
	se, err := ociremote.SignedEntity(ref, ociOpts...)
	if err != nil {
		return nil, mapRegistryError(fmt.Sprintf("sign: accessing %q", cfg.ref), err)
	}

	var rekorClient *client.Rekor
	if cfg.tlogUpload {
		rekorClient, err = rekocli.NewClient(cfg.rekorURL)
		if err != nil {
			return nil, fmt.Errorf("creating Rekor client for %q: %w", cfg.rekorURL, err)
		}
	}

	var results []signResult
	// Without recursive, stop after the root entity (cosign's own behavior).
	errDone := error(nil)
	if !cfg.recursive {
		errDone = mutate.ErrSkipChildren
	}
	err = walk.SignedEntity(ctx, se, func(ctx context.Context, child oci.SignedEntity) error {
		h, derr := child.(interface{ Digest() (v1.Hash, error) }).Digest()
		if derr != nil {
			return fmt.Errorf("computing digest: %w", derr)
		}
		childDigest := ref.Context().Digest(h.String())
		res, serr := p.signOne(ctx, cfg, sign, childDigest, child, ociOpts, opts, rekorClient)
		if serr != nil {
			return serr
		}
		results = append(results, res)
		return errDone
	})
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	root := results[0]
	digests := make([]string, 0, len(results))
	for _, r := range results {
		digests = append(digests, r.digest)
	}

	data := map[string]any{
		"success":          true,
		"ref":              cfg.ref,
		"digest":           desc.Digest.String(),
		"mediaType":        string(desc.MediaType),
		"signature_digest": root.signatureDigest,
		"signed_digests":   digests,
		"referrers_mode":   cfg.referrersMode,
	}
	if root.tlogSet {
		data["tlog_index"] = root.tlogIndex
		data["tlog_url"] = tlogEntryURL(cfg.rekorURL, root.tlogIndex)
	}
	if sign.cert != nil {
		data["certificate"] = string(sign.cert)
	}

	return &sdkprovider.Output{Data: data}, nil
}

// signOne builds the payload for one subject digest, signs it, attaches the
// signature to the entity, and writes it to the registry.
func (p *Plugin) signOne(ctx context.Context, cfg *signConfig, sign *signer, digest name.Digest, se oci.SignedEntity, ociOpts []ociremote.Option, opts []remote.Option, rekorClient *client.Rekor) (signResult, error) {
	res := signResult{digest: digest.DigestStr()}

	payload, err := (&sigpayload.Cosign{
		Image:       digest,
		Annotations: payloadAnnotations(cfg.annotations),
	}).MarshalJSON()
	if err != nil {
		return res, fmt.Errorf("building signature payload: %w", err)
	}
	res.payloadDigest = "sha256:" + hex.EncodeToString(sha256Sum(payload))

	sig, err := sign.sv.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return res, fmt.Errorf("signing payload: %w", err)
	}

	ociSig, err := static.NewSignature(payload, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		return res, fmt.Errorf("creating signature layer: %w", err)
	}
	if sign.cert != nil {
		if ociSig, err = mutate.Signature(ociSig, mutate.WithCertChain(sign.cert, sign.chain)); err != nil {
			return res, fmt.Errorf("attaching certificate: %w", err)
		}
	}
	if rekorClient != nil {
		entry, uerr := p.uploadToRekor(ctx, sign, sig, payload, rekorClient)
		if uerr != nil {
			return res, fmt.Errorf("uploading to transparency log: %w", uerr)
		}
		if entry != nil && entry.LogIndex != nil {
			res.tlogIndex = *entry.LogIndex
			res.tlogSet = true
		}
		var b *cbundle.RekorBundle
		if entry != nil {
			b = cbundle.EntryToBundle(entry)
		}
		if b != nil {
			if ociSig, err = mutate.Signature(ociSig, mutate.WithBundle(b)); err != nil {
				return res, fmt.Errorf("attaching transparency log bundle: %w", err)
			}
		}
	}

	newSE, err := mutate.AttachSignatureToEntity(se, ociSig, mutate.WithDupeDetector(cremote.NewDupeDetector(sign.sv)))
	if err != nil {
		return res, fmt.Errorf("attaching signature to entity: %w", err)
	}

	if cfg.referrersMode == ReferrersModeLegacy {
		if err := ociremote.WriteSignatures(digest.Repository, newSE, ociOpts...); err != nil {
			return res, mapRegistryError("sign: writing signature image", err)
		}
		res.signatureDigest, err = p.lookupLegacySignatureDigest(digest, ociOpts, opts, res.payloadDigest)
		if err != nil {
			return res, err
		}
		return res, nil
	}

	if err := ociremote.WriteSignaturesExperimentalOCI(digest, newSE, ociOpts...); err != nil {
		return res, mapRegistryError("sign: writing signature referrer", err)
	}
	res.signatureDigest, err = p.lookupReferrerSignatureDigest(digest, opts, res.payloadDigest)
	if err != nil {
		return res, err
	}
	return res, nil
}

// uploadToRekor writes the signature to the Rekor transparency log, using
// the signing certificate (keyless; already PEM from Fulcio) or the public
// key (key-based) as the identity material, exactly as cosign does.
func (p *Plugin) uploadToRekor(ctx context.Context, sign *signer, sig, payload []byte, rc *client.Rekor) (*models.LogEntryAnon, error) {
	var rekorBytes []byte
	var err error
	if sign.cert != nil {
		rekorBytes = sign.cert
	} else {
		rekorBytes, err = cryptoutils.MarshalPublicKeyToPEM(sign.sv)
		if err != nil {
			return nil, fmt.Errorf("marshaling public key: %w", err)
		}
	}
	checkSum := sha256.New()
	if _, err := checkSum.Write(payload); err != nil { //nolint:errcheck // sha256 Write never fails
		return nil, err
	}
	return pkgcosign.TLogUpload(ctx, rc, sig, checkSum, rekorBytes)
}

// lookupReferrerSignatureDigest finds the signature referrer manifest that
// carries the payload layer just signed, and returns its manifest digest.
// Matching on the payload blob digest (not on artifact type or ordering)
// keeps this correct when re-signing with additional keys, and robust to
// registries that omit artifactType from referrer listings.
func (p *Plugin) lookupReferrerSignatureDigest(digest name.Digest, opts []remote.Option, payloadDigest string) (string, error) {
	idx, err := remote.Referrers(digest, opts...)
	if err != nil {
		return "", mapRegistryError("sign: listing referrers", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("reading referrers index: %w", err)
	}
	for _, m := range manifest.Manifests {
		child, gerr := remote.Get(digest.Digest(m.Digest.String()), opts...)
		if gerr != nil {
			continue
		}
		if containsLayer(child.Manifest, payloadDigest) {
			return m.Digest.String(), nil
		}
	}
	return "", fmt.Errorf("signature referrer for payload %s not found after write", payloadDigest)
}

// lookupLegacySignatureDigest returns the digest of the signature image the
// legacy write just updated, verifying our payload layer is present.
func (p *Plugin) lookupLegacySignatureDigest(digest name.Digest, ociOpts []ociremote.Option, opts []remote.Option, payloadDigest string) (string, error) {
	sigTag, err := ociremote.SignatureTag(digest, ociOpts...)
	if err != nil {
		return "", fmt.Errorf("resolving signature tag: %w", err)
	}
	desc, err := remote.Get(sigTag, opts...)
	if err != nil {
		return "", mapRegistryError("sign: reading back signature tag", err)
	}
	if !containsLayer(desc.Manifest, payloadDigest) {
		return "", fmt.Errorf("signature layer not present in signature tag %q", sigTag.String())
	}
	return desc.Digest.String(), nil
}

// containsLayer reports whether a raw manifest JSON references payloadDigest.
func containsLayer(rawManifest []byte, payloadDigest string) bool {
	var m v1.Manifest
	if err := json.Unmarshal(rawManifest, &m); err != nil {
		return false
	}
	for _, l := range m.Layers {
		if l.Digest.String() == payloadDigest {
			return true
		}
	}
	return false
}

// buildSigner constructs the signing identity: a key from the key reference,
// or an ephemeral key certified by Fulcio for keyless signing.
func (p *Plugin) buildSigner(ctx context.Context, cfg *signConfig) (*signer, error) {
	if !cfg.keyless {
		sv, err := sigs.SignerVerifierFromKeyRef(ctx, cfg.key, passFunc, nil)
		if err != nil {
			return nil, fmt.Errorf("loading key %q: %w", cfg.key, err)
		}
		return &signer{sv: sv}, nil
	}

	idToken, err := p.oidcToken(ctx, cfg.oidcHandler)
	if err != nil {
		return nil, fmt.Errorf("getting OIDC identity: %w", err)
	}

	privKey, err := pkgcosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("initializing ephemeral signer: %w", err)
	}

	ko := cosignopts.KeyOpts{
		FulcioURL:                cfg.fulcioURL,
		IDToken:                  idToken,
		SkipConfirmation:         true,
		InsecureSkipFulcioVerify: cfg.skipFulcioVerify,
	}
	var fs *fulcio.Signer
	if cfg.skipFulcioVerify {
		fs, err = fulcio.NewSigner(ctx, ko, sv)
	} else {
		fs, err = fulcioverifier.NewSigner(ctx, ko, sv)
	}
	if err != nil {
		return nil, fmt.Errorf("getting certificate from Fulcio: %w", err)
	}
	return &signer{sv: fs, cert: fs.Cert, chain: fs.Chain}, nil
}

// oidcToken sources an OIDC identity token for keyless signing. Ambient
// providers (SIGSTORE_ID_TOKEN, GitHub Actions, SPIFFE, ...) are preferred;
// an explicit oidc_handler falls back to the host auth broker's token, which
// only works against a Fulcio that trusts that handler's issuer (see README).
func (p *Plugin) oidcToken(ctx context.Context, handler string) (string, error) {
	var providerErr error
	if providers.Enabled(ctx) {
		tok, err := providers.Provide(ctx, "sigstore")
		if err == nil && tok != "" {
			return tok, nil
		}
		providerErr = err
	}

	if handler != "" {
		hc := sdkplugin.HostClientFromContext(ctx)
		if hc == nil {
			return "", fmt.Errorf("oidc_handler %q requires the host auth broker, which is unavailable in this context", handler)
		}
		resp, err := hc.GetAuthToken(ctx, handler, p.scope, 60, false)
		if err != nil {
			return "", fmt.Errorf("host auth broker (%s): %w", handler, err)
		}
		if resp.AccessToken == "" {
			return "", fmt.Errorf("host auth broker (%s) returned an empty token", handler)
		}
		return resp.AccessToken, nil
	}

	detail := "no ambient OIDC provider is enabled (set SIGSTORE_ID_TOKEN, run inside GitHub Actions/SPIFFE, ...) and no oidc_handler is configured"
	if providerErr != nil {
		detail = fmt.Sprintf("ambient OIDC provider failed: %v; %s", providerErr, detail)
	}
	return "", errors.New(detail)
}

// parseSignConfig resolves and validates the sign operation inputs. It
// performs no I/O so validation errors are deterministic.
func parseSignConfig(input map[string]any) (*signConfig, error) {
	refStr, err := requireString(input, "ref")
	if err != nil {
		return nil, err
	}

	cfg := &signConfig{ref: refStr}
	cfg.key, _ = input["key"].(string)
	cfg.oidcHandler, _ = input["oidc_handler"].(string)
	cfg.rekorURL, _ = input["rekor_url"].(string)

	if raw, ok := input["keyless"]; ok {
		b, err := toBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid keyless: %w", err)
		}
		if b && cfg.key != "" {
			return nil, fmt.Errorf("set only one of key or keyless, not both")
		}
		if !b && cfg.key == "" {
			return nil, fmt.Errorf("keyless: false requires a key")
		}
		cfg.keyless = b
	} else {
		cfg.keyless = cfg.key == ""
	}

	if cfg.keyless {
		cfg.fulcioURL, _ = input["fulcio_url"].(string)
		if cfg.fulcioURL == "" {
			return nil, fmt.Errorf("fulcio_url is required for keyless signing")
		}
		if raw, ok := input["fulcio_insecure_skip_verify"]; ok {
			b, err := toBool(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid fulcio_insecure_skip_verify: %w", err)
			}
			cfg.skipFulcioVerify = b
		}
	}

	if raw, ok := input["tlog_upload"]; ok {
		b, err := toBool(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid tlog_upload: %w", err)
		}
		cfg.tlogUpload = b
	} else {
		cfg.tlogUpload = cfg.keyless || cfg.rekorURL != ""
	}
	if cfg.tlogUpload && cfg.rekorURL == "" {
		return nil, fmt.Errorf("tlog_upload requires a rekor_url (no endpoint is hardcoded)")
	}

	mode, _ := input["referrers_mode"].(string)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ReferrersModeOCI11:
		cfg.referrersMode = ReferrersModeOCI11
	case ReferrersModeLegacy:
		cfg.referrersMode = ReferrersModeLegacy
	default:
		return nil, fmt.Errorf("invalid referrers_mode %q: expected %q or %q", mode, ReferrersModeOCI11, ReferrersModeLegacy)
	}

	if raw, ok := input["annotations"]; ok {
		anns, err := coerceStringMap(raw)
		if err != nil {
			return nil, fmt.Errorf("field \"annotations\": %w", err)
		}
		cfg.annotations = anns
	}

	recursive, err := wantRecursive(input)
	if err != nil {
		return nil, err
	}
	cfg.recursive = recursive

	return cfg, nil
}

// wantRecursive reports whether the recursive input is set.
func wantRecursive(input map[string]any) (bool, error) {
	raw, ok := input["recursive"]
	if !ok {
		return false, nil
	}
	b, err := toBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid recursive: %w", err)
	}
	return b, nil
}

// payloadAnnotations converts resolved annotations to the payload map shape.
func payloadAnnotations(anns map[string]string) map[string]any {
	if len(anns) == 0 {
		return nil
	}
	m := make(map[string]any, len(anns))
	for k, v := range anns {
		m[k] = v
	}
	return m
}

// tlogEntryURL builds a link to the Rekor entry for the transparency log index.
func tlogEntryURL(rekorURL string, index int64) string {
	return strings.TrimSuffix(rekorURL, "/") + "/api/v1/log/entries?logIndex=" + strconv.FormatInt(index, 10)
}

// getKeychain returns the configured keychain, defaulting to the default keychain.
func (p *Plugin) getKeychain(ctx context.Context) authn.Keychain {
	return buildKeychain(ctx, p.registry, p.username, p.password, p.authHandler, p.scope)
}

// remoteOptions returns the standard remote options for registry interactions.
func (p *Plugin) remoteOptions(ctx context.Context, opts ...remote.Option) []remote.Option {
	base := []remote.Option{
		remote.WithAuthFromKeychain(p.getKeychain(ctx)),
		remote.WithContext(ctx),
	}
	return append(base, opts...)
}

// parseReference wraps name.ParseReference with insecure support and
// friendlier tag validation errors.
func (p *Plugin) parseReference(ref string) (name.Reference, error) {
	var opts []name.Option
	if p.insecure {
		opts = append(opts, name.Insecure)
	}
	parsed, err := name.ParseReference(ref, opts...)
	if err != nil {
		if strings.Contains(ref, "+") {
			return nil, fmt.Errorf("parsing reference %q: tags cannot contain '+' (try replacing with '-'): %w", ref, err)
		}
		return nil, fmt.Errorf("parsing reference %q: %w", ref, err)
	}
	return parsed, nil
}

// sha256Sum is a tiny helper returning the SHA-256 digest bytes of b.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
