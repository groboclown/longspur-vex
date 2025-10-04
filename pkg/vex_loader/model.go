package vexloader

import (
	"github.com/anchore/packageurl-go"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
)

// VexLoader defines the interface for loading VEX documents associated with a given package URL.
// The loader is designed to run in parallel.
type VexLoader interface {
	// LoadVex retrieves VEX documents related to the specified package URL.
	// The VEX may have its own method of discovering the VEX corresponding to the Purl, which
	// may include loading multiple VEX documents.
	// The operation should exit when all loading completes.
	// Because of the way the VEX statements need access, it may require asking for a package's
	// CVE attestations.  In some cases, the loader may not have that level of access before
	// submitting the request, and so may need some post processing.
	LoadVex(
		purl packageurl.PackageURL,
		cveId string,
		vexChan chan<- *vexmodel.VEX,
		errChan chan<- error,
	)
}
