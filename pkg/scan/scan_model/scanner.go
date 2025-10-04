package scanmodel

import (
	"context"

	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
)

type Scanner interface {
	Scan(
		packages []*sbommodel.SbomPackageInfo,
		ctx context.Context,
	) (*ScanResults, error)
}
