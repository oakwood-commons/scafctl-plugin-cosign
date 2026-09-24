// Package main is the entry point for the scafctl-plugin-cosign plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-cosign/internal/cosign"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.Serve(&cosign.Plugin{})
}
