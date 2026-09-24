package cosign

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRetry(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		wantOpts int
		wantErr  bool
	}{
		{name: "unset", input: map[string]any{}, wantOpts: 0},
		{name: "bool false", input: map[string]any{"retry": false}, wantOpts: 0},
		{name: "bool true", input: map[string]any{"retry": true}, wantOpts: 1},
		{name: "integer", input: map[string]any{"retry": 5}, wantOpts: 1},
		{name: "numeric string", input: map[string]any{"retry": "4"}, wantOpts: 1},
		{name: "zero disables", input: map[string]any{"retry": 0}, wantOpts: 0},
		{name: "map full", input: map[string]any{"retry": map[string]any{"attempts": 4, "backoff": "2s", "maxBackoff": "10s"}}, wantOpts: 1},
		{name: "map default attempts", input: map[string]any{"retry": map[string]any{"backoff": "1s"}}, wantOpts: 1},
		{name: "bad backoff", input: map[string]any{"retry": map[string]any{"backoff": "nope"}}, wantErr: true},
		{name: "bad type", input: map[string]any{"retry": []any{1, 2}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := parseRetry(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, opts, tt.wantOpts)
		})
	}
}

func TestMapRegistryError(t *testing.T) {
	t.Run("passes through non-transport errors", func(t *testing.T) {
		err := mapRegistryError("copy", errors.New("boom"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "copy: boom")
	})

	t.Run("manifest invalid yields blob-ordering hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 400,
			Errors:     []transport.Diagnostic{{Code: transport.ManifestInvalidErrorCode, Message: "bad"}},
		}
		err := mapRegistryError("copy", terr)
		assert.Contains(t, err.Error(), "blob-before-manifest")
		assert.ErrorIs(t, err, terr)
	})

	t.Run("unauthorized yields auth hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 401,
			Errors:     []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode, Message: "no"}},
		}
		err := mapRegistryError("push", terr)
		assert.Contains(t, err.Error(), "auth login")
	})

	t.Run("rate limit yields retry hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 429,
			Errors:     []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode, Message: "slow down"}},
		}
		err := mapRegistryError("pull", terr)
		assert.Contains(t, err.Error(), "retry")
	})

	t.Run("status-only fallback", func(t *testing.T) {
		terr := &transport.Error{StatusCode: 403}
		err := mapRegistryError("push", terr)
		assert.Contains(t, err.Error(), "access denied")
	})

	t.Run("manifest unknown yields existence hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 404,
			Errors:     []transport.Diagnostic{{Code: transport.ManifestUnknownErrorCode, Message: "missing"}},
		}
		err := mapRegistryError("pull", terr)
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("denied yields scope hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 403,
			Errors:     []transport.Diagnostic{{Code: transport.DeniedErrorCode, Message: "denied"}},
		}
		err := mapRegistryError("push", terr)
		assert.Contains(t, err.Error(), "access denied")
	})

	t.Run("invalid tag yields naming hint", func(t *testing.T) {
		terr := &transport.Error{
			StatusCode: 400,
			Errors:     []transport.Diagnostic{{Code: transport.TagInvalidErrorCode, Message: "bad tag"}},
		}
		err := mapRegistryError("copy", terr)
		assert.Contains(t, err.Error(), "reference is invalid")
	})

	t.Run("unauthorized status fallback", func(t *testing.T) {
		terr := &transport.Error{StatusCode: 401}
		err := mapRegistryError("pull", terr)
		assert.Contains(t, err.Error(), "authentication required")
	})

	t.Run("rate-limit status fallback", func(t *testing.T) {
		terr := &transport.Error{StatusCode: 429}
		err := mapRegistryError("copy", terr)
		assert.Contains(t, err.Error(), "rate limited")
	})

	t.Run("not-found status fallback", func(t *testing.T) {
		terr := &transport.Error{StatusCode: 404}
		err := mapRegistryError("pull", terr)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("unmapped status passes through", func(t *testing.T) {
		terr := &transport.Error{StatusCode: 500}
		err := mapRegistryError("copy", terr)
		assert.Contains(t, err.Error(), "copy:")
		assert.ErrorIs(t, err, terr)
	})

	t.Run("nil error", func(t *testing.T) {
		assert.NoError(t, mapRegistryError("copy", nil))
	})
}

func TestToDuration(t *testing.T) {
	d, err := toDuration("1500ms")
	require.NoError(t, err)
	assert.Equal(t, 1500*time.Millisecond, d)

	d, err = toDuration(2)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Second, d)

	d, err = toDuration(int64(3))
	require.NoError(t, err)
	assert.Equal(t, 3*time.Second, d)

	d, err = toDuration(1.5)
	require.NoError(t, err)
	assert.Equal(t, 1500*time.Millisecond, d)

	_, err = toDuration([]int{1})
	require.Error(t, err)

	_, err = toDuration("not-a-duration")
	require.Error(t, err)
}

func TestToInt(t *testing.T) {
	tests := []struct {
		name    string
		in      any
		want    int
		wantErr bool
	}{
		{name: "int", in: 5, want: 5},
		{name: "int64", in: int64(6), want: 6},
		{name: "float64", in: 7.0, want: 7},
		{name: "string", in: "8", want: 8},
		{name: "non-integer float", in: 1.9, wantErr: true},
		{name: "bad string", in: "nope", wantErr: true},
		{name: "bad type", in: []int{1}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toInt(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
