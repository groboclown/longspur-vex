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

func Test_DecodeSbomFilenameReader_CSpdx22_NameMatch(t *testing.T) {
	inv, err := detect.DecodeSbomFilenameReader(context.Background(), GetTestResource("c-spdx2.2.spdx"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkCInventory(t, inv)
}

func Test_DecodeSbomFilenameReader_CSpdx22_NoNameMatch(t *testing.T) {
	inv, err := detect.DecodeSbomFilenameReader(context.Background(), GetTestResource("c-spdx2.2.spdx.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkCInventory(t, inv)
}

func Test_DecodeSbomReader_CSpdx22(t *testing.T) {
	inv, err := detect.DecodeSbomReader(context.Background(), GetTestResource("c-spdx2.2.spdx"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkCInventory(t, inv)
}

func Test_DecodeSbomFilenameReader_CSpdx30Json(t *testing.T) {
	inv, err := detect.DecodeSbomFilenameReader(context.Background(), GetTestResource("c-spdx3.0.spdx.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkCInventory(t, inv)
}

func Test_DecodeSbomReader_CSpdx30Json(t *testing.T) {
	inv, err := detect.DecodeSbomReader(context.Background(), GetTestResource("c-spdx3.0.spdx.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkCInventory(t, inv)
}

func checkCInventory(t *testing.T, inv *sbommodel.ReadableSbom) {
	t.Helper()
	// The package has no dependent packages, just external references.
	if len(inv.Packages) != 1 {
		t.Fatalf("expected 0 package, found %d", len(inv.Packages))
	}
}
