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

func Test_DecodeSbomFilenameReader_GoSpdx22Json(t *testing.T) {
	inv, err := detect.DecodeSbomFilenameReader(context.Background(), GetTestResource("go-spdx2.2.spdx.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGoInventory(t, inv)
}

func Test_DecodeSbomReader_GoSpdx22Json(t *testing.T) {
	inv, err := detect.DecodeSbomReader(context.Background(), GetTestResource("go-spdx2.2.spdx.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkGoInventory(t, inv)
}

func checkGoInventory(t *testing.T, inv *sbommodel.ReadableSbom) {
	t.Helper()
	// The package has no dependent packages, just external references.
	if len(inv.Packages) != 0 {
		t.Fatalf("expected 0 package, got %d", len(inv.Packages))
	}
}
