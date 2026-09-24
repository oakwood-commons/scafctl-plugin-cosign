package cosign

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// parseRetry builds retry options from the optional "retry" input.
//
// Accepted shapes:
//   - integer / numeric string: maximum attempts (e.g. 5)
//   - bool true: enable with a sensible default attempt count
//   - map: {attempts: int, backoff: "1s", maxBackoff: "30s"}
//
// When retry is unset the go-containerregistry defaults apply (3 attempts,
// retrying 408/429/5xx), so this only overrides tuning when requested.
func parseRetry(input map[string]any) ([]remote.Option, error) {
	raw, ok := input["retry"]
	if !ok || raw == nil {
		return nil, nil
	}

	attempts := 0
	baseBackoff := time.Second
	var maxBackoff time.Duration

	switch v := raw.(type) {
	case bool:
		if !v {
			return nil, nil
		}
		attempts = 3
	case map[string]any:
		if a, has := v["attempts"]; has {
			n, err := toInt(a)
			if err != nil {
				return nil, fmt.Errorf("invalid retry.attempts: %w", err)
			}
			attempts = n
		} else {
			attempts = 3
		}
		if b, has := v["backoff"]; has {
			d, err := toDuration(b)
			if err != nil {
				return nil, fmt.Errorf("invalid retry.backoff: %w", err)
			}
			baseBackoff = d
		}
		if mb, has := v["maxBackoff"]; has {
			d, err := toDuration(mb)
			if err != nil {
				return nil, fmt.Errorf("invalid retry.maxBackoff: %w", err)
			}
			maxBackoff = d
		}
	default:
		n, err := toInt(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid retry: expected an attempt count or a {attempts, backoff} map, got %T", raw)
		}
		attempts = n
	}

	if attempts <= 0 {
		return nil, nil
	}

	backoff := remote.Backoff{
		Duration: baseBackoff,
		Factor:   2.0,
		Jitter:   0.1,
		Steps:    attempts,
		Cap:      maxBackoff,
	}
	return []remote.Option{remote.WithRetryBackoff(backoff)}, nil
}

// mapRegistryError augments cryptic registry/transport errors with actionable
// guidance while preserving the original error via %w.
func mapRegistryError(context string, err error) error {
	if err == nil {
		return nil
	}

	var terr *transport.Error
	if !errors.As(err, &terr) {
		return fmt.Errorf("%s: %w", context, err)
	}

	if hint := hintForDiagnostics(terr); hint != "" {
		return fmt.Errorf("%s: %s: %w", context, hint, err)
	}
	if hint := hintForStatus(terr.StatusCode); hint != "" {
		return fmt.Errorf("%s: %s: %w", context, hint, err)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// hintForDiagnostics returns an actionable hint for the first recognized OCI
// error code in the transport error, or "" if none match.
func hintForDiagnostics(terr *transport.Error) string {
	for _, diag := range terr.Errors {
		switch diag.Code {
		case transport.ManifestInvalidErrorCode, transport.ManifestBlobUnknownErrorCode, transport.BlobUnknownErrorCode:
			return "the destination registry rejected the manifest because referenced blobs are missing; " +
				"this usually means a blob-before-manifest ordering issue (blobs must be uploaded before the manifest that references them)"
		case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode:
			return "the manifest or repository does not exist on the registry; verify the reference and that you have pull access"
		case transport.UnauthorizedErrorCode:
			return "authentication failed (401); run `scafctl auth login` for this registry or set username/password/token"
		case transport.DeniedErrorCode:
			return "access denied (403); the token lacks push scope for this repository (signature writes push artifacts)"
		case transport.TooManyRequestsErrorCode:
			return "the registry is rate limiting (429); enable retries with the `retry` input or reduce concurrency"
		case transport.TagInvalidErrorCode, transport.NameInvalidErrorCode:
			return "the reference is invalid; tags cannot contain '+' and must match the registry's naming rules"
		}
	}
	return ""
}

// hintForStatus maps a bare HTTP status code to an actionable hint.
func hintForStatus(code int) string {
	switch code {
	case http.StatusUnauthorized:
		return "authentication required (401); run `scafctl auth login` for this registry"
	case http.StatusForbidden:
		return "access denied (403); the token lacks the required scope for this repository"
	case http.StatusTooManyRequests:
		return "rate limited (429); enable retries with the `retry` input or reduce concurrency"
	case http.StatusNotFound:
		return "not found (404); verify the reference exists and you have pull access"
	default:
		return ""
	}
}

// toBool coerces common scalar representations into a bool.
func toBool(v any) (bool, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(b))
		if err != nil {
			return false, fmt.Errorf("expected a boolean, got %q", b)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("expected a boolean, got %T", v)
	}
}

// toInt coerces common numeric representations into an int. Floating-point
// inputs must represent whole numbers within the int range; a fractional value
// such as 1.9 is rejected rather than silently truncated, since these values
// drive retry attempt counts where truncation would be surprising.
func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		if n < math.MinInt || n > math.MaxInt {
			return 0, fmt.Errorf("integer out of range: %v", n)
		}
		return int(n), nil
	case float64:
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("expected a whole number, got %v", n)
		}
		if n < math.MinInt || n > math.MaxInt {
			return 0, fmt.Errorf("integer out of range: %v", n)
		}
		return int(n), nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, fmt.Errorf("expected an integer, got %q", n)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("expected an integer, got %T", v)
	}
}

// toDuration coerces a duration string ("1s", "500ms") or a number of seconds
// into a time.Duration.
func toDuration(v any) (time.Duration, error) {
	switch d := v.(type) {
	case string:
		parsed, err := time.ParseDuration(strings.TrimSpace(d))
		if err != nil {
			return 0, fmt.Errorf("expected a duration such as \"1s\", got %q", d)
		}
		return parsed, nil
	case int:
		return time.Duration(d) * time.Second, nil
	case int64:
		return time.Duration(d) * time.Second, nil
	case float64:
		return time.Duration(d * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("expected a duration string or number of seconds, got %T", v)
	}
}

// coerceStringMap normalizes a value to map[string]string.
// Accepts map[string]any or a comma-separated string of key=value pairs (for CLI use).
func coerceStringMap(v any) (map[string]string, error) {
	switch val := v.(type) {
	case map[string]any:
		m := make(map[string]string, len(val))
		for k, v := range val {
			m[k] = fmt.Sprintf("%v", v)
		}
		return m, nil
	case string:
		m := make(map[string]string)
		for _, part := range strings.Split(val, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				return nil, fmt.Errorf("entry %q must be in key=value format", part)
			}
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("expected object or comma-separated key=value string, got %T", v)
	}
}
