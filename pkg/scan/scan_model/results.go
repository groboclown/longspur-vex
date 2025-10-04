package scanmodel

import (
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ScanResults struct {
	Packages []*PackageScanResults
}

type PackageScanResults struct {
	Package *sbommodel.SbomPackageInfo
	// Eventually, may want to maintain an internal vulnerability model.
	Vulnerabilities []*osvschema.Vulnerability
}

type License struct {
	SPDX       string
	Confidence float64
}
