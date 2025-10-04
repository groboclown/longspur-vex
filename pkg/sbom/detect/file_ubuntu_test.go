/*
SPDX-License-Identifier: Apache-2.0
*/
package detect_test

import (
	"context"
	"testing"

	"github.com/groboclown/cve-longspur/pkg/sbom/detect"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
)

func Test_Ubuntu(t *testing.T) {
	tests := []string{
		"ubuntu.cdx.json",
		"ubuntu.cdx.xml",
		"ubuntu.spdx2.2.spdx.json",
		"ubuntu.spdx2.2.spdx",
		"ubuntu.spdx2.3.spdx.json",
		"ubuntu.spdx2.3.spdx",
		"ubuntu.syft.json",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			inv, err := detect.DecodeSbomFilenameReader(
				context.Background(), GetTestResource(name),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			checkUbuntuInventory(t, inv)
		})
	}
}

func checkUbuntuInventory(t *testing.T, inv *sbommodel.ReadableSbom) {
	t.Helper()
	// The package has no dependent packages, just external references.
	if len(inv.Packages) != 93 {
		t.Fatalf("expected 93 package, got %d", len(inv.Packages))
	}
}
