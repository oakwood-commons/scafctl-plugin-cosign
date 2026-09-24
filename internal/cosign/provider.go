// Package cosign implements the cosign signing provider plugin.
//
// Everything runs in-process with the embedded sigstore libraries — no
// `cosign` binary is ever invoked (no os/exec anywhere in this package).
// This is the no-shell guarantee that replaces `cosign sign` in CI.
package cosign

import (
	"context"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/jsonschema-go/jsonschema"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	sdkhelper "github.com/oakwood-commons/scafctl-plugin-sdk/provider/schemahelper"
)

const (
	// ProviderName is the unique identifier for this provider.
	ProviderName = "cosign"
)

// version is the provider version, settable via ldflags.
var version = "0.1.0"

// Operations supported by the cosign provider.
const (
	OpSign = "sign"
)

// Plugin implements the scafctl ProviderPlugin interface.
type Plugin struct {
	// Static credentials from ConfigureProvider settings.
	registry    string
	username    string
	password    string
	authHandler string
	scope       string
	insecure    bool
}

// Ensure Plugin implements the required interface.
var _ sdkplugin.ProviderPlugin = (*Plugin)(nil)

// GetProviders returns the list of providers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetProviders(_ context.Context) ([]string, error) {
	return []string{ProviderName}, nil
}

// GetProviderDescriptor returns the descriptor for the named provider.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetProviderDescriptor(_ context.Context, providerName string) (*sdkprovider.Descriptor, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	parsedVersion, err := semver.NewVersion(version)
	if err != nil {
		return nil, fmt.Errorf("invalid provider version %q: %w", version, err)
	}

	return &sdkprovider.Descriptor{
		Name:        ProviderName,
		DisplayName: "Cosign Signing Provider",
		Description: "Daemonless OCI artifact signing with embedded sigstore libraries. Signs a pushed artifact by digest, stores the signature as an OCI 1.1 referrer, and optionally logs it to Rekor — no cosign binary required.",
		APIVersion:  "v1",
		Version:     parsedVersion,
		Category:    "security",
		Capabilities: []sdkprovider.Capability{
			sdkprovider.CapabilityAction,
		},
		WriteOperations: []string{OpSign},
		Schema:          buildInputSchema(),
		OutputSchemas:   buildOutputSchemas(),
	}, nil
}

// ExecuteProvider executes the named provider with the given input.
func (p *Plugin) ExecuteProvider(ctx context.Context, providerName string, input map[string]any) (*sdkprovider.Output, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	if input == nil {
		return nil, fmt.Errorf("input is required")
	}

	op, _ := input["operation"].(string)
	if op == "" {
		return nil, fmt.Errorf("required field 'operation' is missing")
	}

	switch op {
	case OpSign:
		return p.executeSign(ctx, input)
	default:
		return nil, fmt.Errorf("unknown operation: %s", op)
	}
}

// DescribeWhatIf returns a description of what the provider would do.
// It performs no I/O and never resolves the ref; that is left to execution.
//
//nolint:revive // ctx required by interface
func (p *Plugin) DescribeWhatIf(_ context.Context, providerName string, input map[string]any) (string, error) {
	if providerName != ProviderName {
		return "", fmt.Errorf("unknown provider: %s", providerName)
	}

	if input == nil {
		return "Would perform no operation (nil input)", nil
	}

	op, _ := input["operation"].(string)
	ref, _ := input["ref"].(string)

	switch op {
	case OpSign:
		key, _ := input["key"].(string)
		rekorURL, _ := input["rekor_url"].(string)
		mode := referrersModeFromInput(input)

		who := "keyless (OIDC identity via Fulcio)"
		if key != "" {
			who = fmt.Sprintf("key-based key %s", key)
		}

		parts := []string{
			fmt.Sprintf("Would sign %s (resolving to its digest first) using %s", ref, who),
		}
		switch mode {
		case ReferrersModeLegacy:
			parts = append(parts, "storing the signature under the legacy sha256-<digest>.sig tag")
		default:
			parts = append(parts, "storing the signature as an OCI 1.1 referrer")
		}
		if rekorURL != "" {
			parts = append(parts, fmt.Sprintf("and logging it to Rekor at %s", rekorURL))
		}
		if err := whatIfBool(input, "keyless"); err != nil {
			return "", err
		}
		recursive, err := wantRecursive(input)
		if err != nil {
			return "", err
		}
		if recursive {
			parts = append(parts, "for the index and every child manifest")
		}
		if n := countAnnotations(input); n > 0 {
			parts = append(parts, fmt.Sprintf("with %d annotation(s)", n))
		}
		return strings.Join(parts, ", "), nil
	default:
		return fmt.Sprintf("Would perform unknown operation %q", op), nil
	}
}

// whatIfBool validates a boolean input's type for WhatIf parity without
// failing on absent fields, so dry runs surface the same errors as execution.
func whatIfBool(input map[string]any, field string) error {
	raw, has := input[field]
	if !has {
		return nil
	}
	if _, err := toBool(raw); err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	return nil
}

// referrersModeFromInput extracts and normalizes referrers_mode for WhatIf,
// defaulting to oci-1-1 without failing on invalid input (dry runs stay
// informational; execution performs the strict validation).
func referrersModeFromInput(input map[string]any) string {
	mode, _ := input["referrers_mode"].(string)
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ReferrersModeLegacy:
		return ReferrersModeLegacy
	default:
		return ReferrersModeOCI11
	}
}

// countAnnotations returns the number of signature annotations in the input.
func countAnnotations(input map[string]any) int {
	raw, has := input["annotations"]
	if !has {
		return 0
	}
	if m, err := coerceStringMap(raw); err == nil {
		return len(m)
	}
	return 0
}

// requireString extracts a required string field from input or returns an error.
func requireString(input map[string]any, field string) (string, error) {
	v, _ := input[field].(string)
	if v == "" {
		return "", fmt.Errorf("required field %q is missing or empty", field)
	}
	return v, nil
}

// stringOrMapSchema returns a JSON Schema that accepts a comma-separated string or an object map.
func stringOrMapSchema(description string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Description: description,
		OneOf: []*jsonschema.Schema{
			sdkhelper.StringProp("comma-separated key=value pairs"),
			sdkhelper.ObjectProp("map of key-value pairs", nil, nil),
		},
	}
}

func buildInputSchema() *jsonschema.Schema {
	return sdkhelper.ObjectSchema(
		[]string{"operation"},
		map[string]*jsonschema.Schema{
			"operation": sdkhelper.StringProp(
				"The operation to perform",
				sdkhelper.WithEnum(OpSign),
			),
			"ref": sdkhelper.StringProp(
				"Artifact to sign. A digest ref (repo@sha256:...) is signed as-is; a tag ref (repo:tag) is resolved to its digest first, and the digest is what gets signed",
				sdkhelper.WithExample("ghcr.io/myorg/myapp@sha256:abc123..."),
			),
			"key": sdkhelper.StringProp(
				"cosign key reference for key-based signing: a file path, env://VAR, k8s://namespace/secret, or a KMS reference. Omit for keyless (OIDC) signing",
				sdkhelper.WithExample("./cosign.key"),
			),
			"keyless": sdkhelper.BoolProp(
				"Force keyless (OIDC) signing. Defaults to true when key is absent; cannot be combined with key",
			),
			"oidc_handler": sdkhelper.StringProp(
				"scafctl auth handler to source the OIDC identity from when no ambient provider is available. Only works if the target Fulcio trusts the handler's tokens",
				sdkhelper.WithExample("entra"),
			),
			"fulcio_url": sdkhelper.StringProp(
				"Fulcio CA that issues the ephemeral signing certificate (required for keyless signing)",
				sdkhelper.WithExample("https://fulcio.sigstore.dev"),
			),
			"rekor_url": sdkhelper.StringProp(
				"Rekor transparency log endpoint. When set (and tlog_upload is not disabled), the signature is logged. No hardcoded default — configure your deployment's endpoint",
				sdkhelper.WithExample("https://rekor.sigstore.dev"),
			),
			"tlog_upload": sdkhelper.BoolProp(
				"Upload the signature to Rekor. Defaults to true for keyless (verification needs the tlog entry), true for key-based when rekor_url is given, false otherwise",
			),
			"referrers_mode": sdkhelper.StringProp(
				"Where the signature is stored: oci-1-1 (default) writes an OCI 1.1 Referrer artifact; legacy writes the tag-based sha256-<digest>.sig scheme",
				sdkhelper.WithEnum(ReferrersModeOCI11, ReferrersModeLegacy),
			),
			"annotations": stringOrMapSchema(
				"Signature annotations, embedded in the signed payload. Accepts a map or comma-separated key=value string",
			),
			"recursive": sdkhelper.BoolProp(
				"Also sign the child manifests of a multi-arch index (the index digest is always signed)",
			),
			"fulcio_insecure_skip_verify": sdkhelper.BoolProp(
				"Skip Fulcio's client-side SCT verification. Needed for private Fulcio deployments whose CT log keys are not in the public sigstore TUF root",
			),
			"retry": sdkhelper.AnyProp(
				"Retry tuning for signature registry writes. Accepts true to enable defaults, an integer " +
					"attempt count, or a map {attempts: int, backoff: \"1s\", maxBackoff: \"30s\"}. Defaults retry 408/429/5xx responses",
			),
		},
	)
}

func buildOutputSchemas() map[sdkprovider.Capability]*jsonschema.Schema {
	return map[sdkprovider.Capability]*jsonschema.Schema{
		sdkprovider.CapabilityAction: sdkhelper.ObjectSchema(nil, map[string]*jsonschema.Schema{
			"success":          sdkhelper.BoolProp("Whether the operation succeeded"),
			"ref":              sdkhelper.StringProp("Signed artifact reference as given"),
			"digest":           sdkhelper.StringProp("Digest of the signed subject manifest (sha256:...)"),
			"mediaType":        sdkhelper.StringProp("Signed subject manifest media type"),
			"signature_digest": sdkhelper.StringProp("Digest of the signature artifact: the referrer manifest (oci-1-1) or the signature image (legacy)"),
			"signed_digests":   sdkhelper.ArrayProp("All digests signed (subject plus child manifests when recursive)", sdkhelper.WithItems(sdkhelper.StringProp("sha256:..."))),
			"referrers_mode":   sdkhelper.StringProp("Referrers mode used (oci-1-1 or legacy)"),
			"tlog_index":       sdkhelper.IntProp("Rekor transparency log index of the signature entry, when uploaded"),
			"tlog_url":         sdkhelper.StringProp("URL of the Rekor entry, when uploaded"),
			"certificate":      sdkhelper.StringProp("PEM of the Fulcio-issued ephemeral signing certificate (keyless only)"),
			"error":            sdkhelper.StringProp("Error message on failure"),
		}),
	}
}

// ConfigureProvider stores host-side configuration.
//
//nolint:revive // ctx required by interface
func (p *Plugin) ConfigureProvider(_ context.Context, providerName string, cfg sdkplugin.ProviderConfig) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}

	if cfg.Settings == nil {
		return nil
	}

	p.registry = getSettingString(cfg.Settings, "registry")
	p.username = getSettingString(cfg.Settings, "username")
	p.password = getSettingString(cfg.Settings, "password")
	p.authHandler = getSettingString(cfg.Settings, "auth_handler")
	p.scope = getSettingString(cfg.Settings, "scope")
	p.insecure = getSettingBool(cfg.Settings, "insecure")

	return nil
}

// ExecuteProviderStream is not supported.
//
//nolint:revive // all params required by interface
func (p *Plugin) ExecuteProviderStream(_ context.Context, providerName string, _ map[string]any, _ func(sdkplugin.StreamChunk)) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}
	return sdkplugin.ErrStreamingNotSupported
}

// ExtractDependencies returns resolver keys this input depends on.
//
//nolint:revive // all params required by interface
func (p *Plugin) ExtractDependencies(_ context.Context, providerName string, _ map[string]any) ([]string, error) {
	if providerName != ProviderName {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}
	return nil, nil
}

// StopProvider performs cleanup for the named provider.
//
//nolint:revive // ctx required by interface
func (p *Plugin) StopProvider(_ context.Context, providerName string) error {
	if providerName != ProviderName {
		return fmt.Errorf("unknown provider: %s", providerName)
	}
	return nil
}
