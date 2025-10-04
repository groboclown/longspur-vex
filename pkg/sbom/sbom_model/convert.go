package sbommodel

import (
	"github.com/groboclown/cve-longspur/pkg/longspurio"
)

// ConvertDependencyTree converts a pre-built dependency "tree" into a ReadableSbom.
// The "tree" can also be a forest of multiple trees.
func ConvertDependencyTree(
	input *longspurio.RelResource,
	tree []*SbomPackageDependencies,
) (*ReadableSbom, error) {
	// Note that, in some cases, this may reference other documents
	// (ExternalDocuments) which require
	// fetching those documents and processing them as well.  However, that introduces
	// extra requirements from the user to grant permissions to download.

	errs := []error{}
	var all []*SbomPackage = nil
	var roots []*SbomPackage = nil

	if tree != nil {
		var err error
		all, roots, err = GeneratePackages(tree)
		if err != nil {
			errs = append(errs, err)
		}
	}
	reader, err := input.OpenReader()
	if err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 || all == nil {
		return nil, NewSbomParseError(input.Path(), errs)
	}
	return &ReadableSbom{
		Sbom: Sbom{
			Source:       input.Path(),
			Packages:     all,
			RootPackages: ExtractPurlsFromPackages(roots),
		},
		Reader: reader,
	}, nil
}
