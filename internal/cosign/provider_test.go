package cosign

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	sdkprovider "github.com/oakwood-commons/scafctl-plugin-sdk/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetProviders(t *testing.T) {
	p := &Plugin{}
	providers, err := p.GetProviders(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{ProviderName}, providers)
}

func TestGetProviderDescriptor(t *testing.T) {
	p := &Plugin{}

	t.Run("known provider", func(t *testing.T) {
		desc, err := p.GetProviderDescriptor(context.Background(), ProviderName)
		require.NoError(t, err)
		assert.Equal(t, ProviderName, desc.Name)
		assert.Equal(t, "Cosign Signing Provider", desc.DisplayName)
		assert.NotEmpty(t, desc.Description)
		assert.NotNil(t, desc.Schema)
		assert.Equal(t, []sdkprovider.Capability{sdkprovider.CapabilityAction}, desc.Capabilities)
		assert.Equal(t, []string{OpSign}, desc.WriteOperations)
		assert.Equal(t, "security", desc.Category)
		assert.NotNil(t, desc.OutputSchemas, "OutputSchemas must be present")
		for _, cap := range desc.Capabilities {
			assert.Contains(t, desc.OutputSchemas, cap, "OutputSchemas must include capability %s", cap)
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.GetProviderDescriptor(context.Background(), "unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

func TestExecuteProvider_UnknownProvider(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExecuteProvider(context.Background(), "unknown", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExecuteProvider_MissingOperation(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "operation")
}

func TestExecuteProvider_NilInput(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExecuteProvider(context.Background(), ProviderName, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input is required")
}

func TestExecuteProvider_UnknownOperation(t *testing.T) {
	p := &Plugin{}
	_, err := p.ExecuteProvider(context.Background(), ProviderName, map[string]any{"operation": "verify"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown operation")
}

func TestConfigureProvider(t *testing.T) {
	p := &Plugin{}

	t.Run("unknown provider", func(t *testing.T) {
		err := p.ConfigureProvider(context.Background(), "unknown", sdkplugin.ProviderConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})

	t.Run("empty settings", func(t *testing.T) {
		require.NoError(t, p.ConfigureProvider(context.Background(), ProviderName, sdkplugin.ProviderConfig{}))
		assert.Empty(t, p.registry)
	})

	t.Run("reads known settings", func(t *testing.T) {
		settings := map[string]json.RawMessage{
			"registry":     json.RawMessage(`"ghcr.io"`),
			"username":     json.RawMessage(`"user"`),
			"password":     json.RawMessage(`"pass"`),
			"auth_handler": json.RawMessage(`"github"`),
			"scope":        json.RawMessage(`"read:packages"`),
			"insecure":     json.RawMessage(`true`),
		}
		require.NoError(t, p.ConfigureProvider(context.Background(), ProviderName, sdkplugin.ProviderConfig{Settings: settings}))
		assert.Equal(t, "ghcr.io", p.registry)
		assert.Equal(t, "user", p.username)
		assert.Equal(t, "pass", p.password)
		assert.Equal(t, "github", p.authHandler)
		assert.Equal(t, "read:packages", p.scope)
		assert.True(t, p.insecure)
	})
}

func TestExecuteProviderStream_NotSupported(t *testing.T) {
	p := &Plugin{}
	err := p.ExecuteProviderStream(context.Background(), ProviderName, nil, nil)
	assert.ErrorIs(t, err, sdkplugin.ErrStreamingNotSupported)

	err = p.ExecuteProviderStream(context.Background(), "unknown", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestExtractDependencies(t *testing.T) {
	p := &Plugin{}
	deps, err := p.ExtractDependencies(context.Background(), ProviderName, nil)
	require.NoError(t, err)
	assert.Empty(t, deps)

	_, err = p.ExtractDependencies(context.Background(), "unknown", nil)
	assert.Error(t, err)
}

func TestStopProvider(t *testing.T) {
	p := &Plugin{}
	require.NoError(t, p.StopProvider(context.Background(), ProviderName))
	assert.Error(t, p.StopProvider(context.Background(), "unknown"))
}

func TestParseSignConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]any
		wantKey   bool // key-based signing expected
		checkFunc func(t *testing.T, cfg *signConfig)
		wantErr   string
	}{
		{
			name:  "key-based defaults",
			input: map[string]any{"ref": "ghcr.io/org/app:v1", "key": "/keys/cosign.key"},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.False(t, cfg.keyless)
				assert.False(t, cfg.tlogUpload, "key-based signing must not upload to the tlog without rekor_url")
				assert.Equal(t, ReferrersModeOCI11, cfg.referrersMode)
				assert.False(t, cfg.recursive)
			},
		},
		{
			name:  "key-based defaults to tlog upload when rekor_url set",
			input: map[string]any{"ref": "r", "key": "k", "rekor_url": "https://rekor.example.com"},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.True(t, cfg.tlogUpload)
				assert.Equal(t, "https://rekor.example.com", cfg.rekorURL)
			},
		},
		{
			name:  "keyless defaults",
			input: map[string]any{"ref": "r", "fulcio_url": "https://fulcio.example.com", "rekor_url": "https://rekor.example.com"},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.True(t, cfg.keyless)
				assert.True(t, cfg.tlogUpload, "keyless signing uploads to the tlog by default")
			},
		},
		{
			name:    "keyless requires fulcio_url",
			input:   map[string]any{"ref": "r"},
			wantErr: "fulcio_url is required for keyless signing",
		},
		{
			name:    "key and keyless conflict",
			input:   map[string]any{"ref": "r", "key": "k", "keyless": true, "fulcio_url": "u"},
			wantErr: "set only one of key or keyless",
		},
		{
			name:    "keyless false without key",
			input:   map[string]any{"ref": "r", "keyless": false},
			wantErr: "keyless: false requires a key",
		},
		{
			name:  "tlog disabled explicitly",
			input: map[string]any{"ref": "r", "fulcio_url": "u", "tlog_upload": false},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.False(t, cfg.tlogUpload)
			},
		},
		{
			name:    "keyless tlog default requires rekor_url",
			input:   map[string]any{"ref": "r", "fulcio_url": "u"},
			wantErr: "tlog_upload requires a rekor_url",
		},
		{
			name:    "explicit tlog_upload requires rekor_url",
			input:   map[string]any{"ref": "r", "key": "k", "tlog_upload": true},
			wantErr: "tlog_upload requires a rekor_url",
		},
		{
			name:  "legacy mode",
			input: map[string]any{"ref": "r", "key": "k", "referrers_mode": "legacy"},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.Equal(t, ReferrersModeLegacy, cfg.referrersMode)
			},
		},
		{
			name:    "invalid referrers_mode",
			input:   map[string]any{"ref": "r", "key": "k", "referrers_mode": "sidecar"},
			wantErr: "invalid referrers_mode",
		},
		{
			name:  "mode and case normalization",
			input: map[string]any{"ref": "r", "key": "k", "referrers_mode": " OCI-1-1 "},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.Equal(t, ReferrersModeOCI11, cfg.referrersMode)
			},
		},
		{
			name:  "annotations map",
			input: map[string]any{"ref": "r", "key": "k", "annotations": map[string]any{"org.opencontainers.image.source": "https://github.com/org/repo"}},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.Equal(t, map[string]string{"org.opencontainers.image.source": "https://github.com/org/repo"}, cfg.annotations)
			},
		},
		{
			name:  "annotations comma string",
			input: map[string]any{"ref": "r", "key": "k", "annotations": "a=b,c=d"},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.Equal(t, map[string]string{"a": "b", "c": "d"}, cfg.annotations)
			},
		},
		{
			name:    "invalid annotations type",
			input:   map[string]any{"ref": "r", "key": "k", "annotations": 42},
			wantErr: "field \"annotations\"",
		},
		{
			name:  "recursive",
			input: map[string]any{"ref": "r", "key": "k", "recursive": true},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.True(t, cfg.recursive)
			},
		},
		{
			name:    "invalid recursive type",
			input:   map[string]any{"ref": "r", "key": "k", "recursive": "yes!"},
			wantErr: "invalid recursive",
		},
		{
			name:    "invalid keyless type",
			input:   map[string]any{"ref": "r", "keyless": 3},
			wantErr: "invalid keyless",
		},
		{
			name:    "invalid tlog_upload type",
			input:   map[string]any{"ref": "r", "key": "k", "tlog_upload": "nope"},
			wantErr: "invalid tlog_upload",
		},
		{
			name:  "skip fulcio verify",
			input: map[string]any{"ref": "r", "fulcio_url": "u", "rekor_url": "re", "fulcio_insecure_skip_verify": true},
			checkFunc: func(t *testing.T, cfg *signConfig) {
				assert.True(t, cfg.skipFulcioVerify)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseSignConfig(tt.input)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
			if tt.checkFunc != nil {
				tt.checkFunc(t, cfg)
			}
		})
	}
}

func TestParseSignConfig_MissingRef(t *testing.T) {
	_, err := parseSignConfig(map[string]any{"key": "k"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"ref"`)
}

func TestDescribeWhatIf(t *testing.T) {
	p := &Plugin{}
	ctx := context.Background()

	t.Run("unknown provider", func(t *testing.T) {
		_, err := p.DescribeWhatIf(ctx, "unknown", nil)
		assert.Error(t, err)
	})

	t.Run("nil input", func(t *testing.T) {
		msg, err := p.DescribeWhatIf(ctx, ProviderName, nil)
		require.NoError(t, err)
		assert.Contains(t, msg, "no operation")
	})

	t.Run("unknown operation", func(t *testing.T) {
		msg, err := p.DescribeWhatIf(ctx, ProviderName, map[string]any{"operation": "nonsense"})
		require.NoError(t, err)
		assert.Contains(t, msg, "unknown operation")
	})

	t.Run("key-based with rekor", func(t *testing.T) {
		msg, err := p.DescribeWhatIf(ctx, ProviderName, map[string]any{
			"operation":   OpSign,
			"ref":         "ghcr.io/org/app:v1",
			"key":         "./cosign.key",
			"rekor_url":   "https://rekor.example.com",
			"recursive":   true,
			"annotations": map[string]any{"env": "prod"},
		})
		require.NoError(t, err)
		assert.Contains(t, msg, "ghcr.io/org/app:v1")
		assert.Contains(t, msg, "resolving to its digest first")
		assert.Contains(t, msg, "key-based")
		assert.Contains(t, msg, "OCI 1.1 referrer")
		assert.Contains(t, msg, "rekor.example.com")
		assert.Contains(t, msg, "child manifest")
		assert.Contains(t, msg, "1 annotation")
	})

	t.Run("keyless legacy mode", func(t *testing.T) {
		msg, err := p.DescribeWhatIf(ctx, ProviderName, map[string]any{
			"operation":      OpSign,
			"ref":            "ghcr.io/org/app:v1",
			"fulcio_url":     "https://fulcio.example.com",
			"referrers_mode": "legacy",
		})
		require.NoError(t, err)
		assert.Contains(t, msg, "keyless")
		assert.Contains(t, msg, "legacy")
	})

	t.Run("invalid keyless type surfaces error", func(t *testing.T) {
		_, err := p.DescribeWhatIf(ctx, ProviderName, map[string]any{
			"operation": OpSign,
			"ref":       "r",
			"keyless":   []int{1},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keyless")
	})
}

func TestTlogEntryURL(t *testing.T) {
	assert.Equal(t,
		"https://rekor.example.com/api/v1/log/entries?logIndex=42",
		tlogEntryURL("https://rekor.example.com/", 42))
}

// TestNoShellOut locks the AC #3 guarantee: no code in this repo — production
// or test — may invoke an external binary. Everything is in-process, to the
// point that even interop with `cosign verify` is proven through cosign's own
// libraries (see verify_test.go). The check parses imports rather than
// grepping text, so comments cannot satisfy or trip it.
func TestNoShellOut(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		fset := token.NewFileSet()
		fh, perr := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		require.NoError(t, perr, "parsing %s", f)
		for _, imp := range fh.Imports {
			assert.NotEqual(t, "os/exec", strings.Trim(imp.Path.Value, `"`),
				"%s must not shell out to external binaries", f)
		}
	}
}
