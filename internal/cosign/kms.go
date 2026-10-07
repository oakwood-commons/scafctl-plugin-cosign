package cosign

import (
	"fmt"
	"sort"
	"strings"

	// Link the sigstore KMS backends so KMS key references (gcpkms://,
	// awskms://, azurekms://, hashivault://) are handled in-process. cosign's
	// own binary does this in its main.go; without these imports any KMS
	// reference would fall through to sigstore's external cliplugin, which
	// tries to exec a sigstore-kms-<scheme> binary and breaks the no-shell
	// guarantee (see TestNoShellOut).
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"

	kubernetes "github.com/sigstore/cosign/v2/pkg/cosign/kubernetes"
	"github.com/sigstore/sigstore/pkg/signature/kms"
)

// selfHandledKeyPrefixes are the key reference prefixes cosign's own key
// loading handles in-process (blob.LoadFileOrURL and the k8s secret loader).
// pkcs11 (hardware tokens) is deliberately excluded: it requires a cgo build
// this plugin does not ship. gitlab:// secret fetching is also excluded to
// keep the supported surface explicit.
var selfHandledKeyPrefixes = []string{
	"env://",
	"http://",
	"https://",
	kubernetes.KeyReference, // k8s://
}

// validateKeyRef rejects key references whose scheme is not handled
// in-process before they reach sigstore's KMS resolver: an unregistered
// scheme:// reference falls through to the external cliplugin, which execs a
// sigstore-kms-<scheme> binary — usually missing on the host, and a shell-out
// this provider must never perform. Registered KMS backends (gcpkms://,
// awskms://, azurekms://, hashivault://), env://, http(s)://, k8s://
// references, and plain file paths all pass.
//
// Residual, accepted: for env:// and http(s):// references sigstore's KMS
// resolver still probes for a sigstore-kms-env / sigstore-kms-http binary
// before falling back to its own blob loader (sigstore kms.Get consults the
// cliplugin for any ref containing "://"). That is sigstore's own behavior,
// identical to the stock CLI: the probe only matters if someone deliberately
// installs a plugin binary with that exact name, which is then a supported
// sigstore extension mechanism, not an escape hatch.
func validateKeyRef(keyRef string) error {
	if keyRef == "" {
		return nil
	}
	if strings.HasPrefix(keyRef, "pkcs11:") {
		return fmt.Errorf("key reference %q: hardware token (pkcs11) keys are not supported in this build", keyRef)
	}
	if isHandledKeyPrefix(keyRef) {
		return nil
	}
	if !strings.Contains(keyRef, "://") {
		return nil // plain file path
	}
	scheme, _, _ := strings.Cut(keyRef, "://")
	return fmt.Errorf("unsupported key scheme %q: supported schemes are %s, plus plain file paths", scheme, strings.Join(supportedKeySchemes(), ", "))
}

// isHandledKeyPrefix reports whether keyRef starts with a prefix served by a
// registered provider or handled by cosign itself.
func isHandledKeyPrefix(keyRef string) bool {
	for _, p := range append(kms.SupportedProviders(), selfHandledKeyPrefixes...) {
		if strings.HasPrefix(keyRef, p) {
			return true
		}
	}
	return false
}

// supportedKeySchemes returns the sorted list of scheme prefixes accepted
// besides plain file paths, for error messages and documentation.
func supportedKeySchemes() []string {
	schemes := append(kms.SupportedProviders(), selfHandledKeyPrefixes...)
	sort.Strings(schemes)
	return schemes
}
