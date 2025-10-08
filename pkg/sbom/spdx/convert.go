package spdx

import (
	"strings"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/spdx"
)

func ConvertSpdx(input *longspurio.RelResource, spdxDoc *spdx.Document) (*sbommodel.ReadableSbom, error) {
	// Note that, in some cases, this may reference other documents
	// (ExternalDocuments) which require
	// fetching those documents and processing them as well.  However, that introduces
	// extra requirements from the user to grant permissions to download.

	errs := []error{}
	tree, err_list := parseSpdxToDependencies(input.Path(), spdxDoc)
	if len(err_list) > 0 {
		errs = append(errs, err_list...)
	}
	sbom, err := sbommodel.ConvertDependencyTree(input, tree)
	if err != nil {
		errs = append(errs, err)
	}
	if sbom == nil || len(errs) > 0 {
		return nil, sbommodel.NewSbomParseError(input.Path(), errs)
	}
	return sbom, nil
}

func parseSpdxToDependencies(path string, spdxDoc *spdx.Document) ([]*sbommodel.SbomPackageDependencies, []error) {
	if spdxDoc == nil {
		return nil, nil
	}
	errs := []error{}
	pkgs := make([]*sbommodel.SbomPackageInfo, 0)

	// First, convert all packages.
	for _, p := range spdxDoc.Packages {
		pkg, err := convertSpdxPackageToInfo(path, p)
		if err != nil {
			errs = append(errs, err)
		} else if pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	// Next, build the dependency tree.
	tree := make([]*sbommodel.SbomPackageDependencies, 0, len(pkgs))
	for _, p := range pkgs {
		pkgDep := fillSpdxDependencies(p, spdxDoc)
		if pkgDep != nil {
			tree = append(tree, pkgDep)
		}
	}

	return tree, errs
}

func convertSpdxPackageToInfo(path string, p *spdx.Package) (*sbommodel.SbomPackageInfo, error) {
	if p == nil {
		return nil, nil
	}
	purl := ""
	for _, extId := range p.PackageExternalReferences {
		if extId.RefType == "purl" {
			purl = extId.Locator
			break
		}
	}
	var parsedPurl *packageurl.PackageURL = nil
	if purl != "" {
		pp, err := packageurl.FromString(purl)
		if err != nil {
			return nil, err
		}
		parsedPurl = &pp
	}
	if parsedPurl == nil && spdxIsValidString(p.PackageName) {
		// Try to guess it.  This could be the primary (root) package.
		parsedPurl = packageurl.NewPackageURL(
			"internal",               // type
			"internal",               // namespace
			p.PackageName,            // name
			p.PackageVersion,         // version
			[]packageurl.Qualifier{}, // qualifiers
			"",                       // subpath
		)
	} else {
		// Doesn't look like a package.
		return nil, nil
	}

	return sbommodel.NewSbomPackageInfo(&sbommodel.RawPackage{
		Name:        p.PackageName,
		Version:     &p.PackageVersion,
		Purl:        *parsedPurl,
		Identifiers: spdxExtractIdentifiers(p),
		Licenses:    spdxExtractLicenses(p),
		Copyright:   spdxExtractCopyrights(p),
		Locations:   spdxExtractLocations(p),
	}, p, path)
}

func spdxExtractLicenses(pkg *spdx.Package) []string {
	if pkg == nil {
		return nil
	}
	if spdxIsValidString(pkg.PackageLicenseConcluded) {
		// The evaluated license that should be in SPDX format.
		return []string{pkg.PackageLicenseConcluded}
	}
	if spdxIsValidString(pkg.PackageLicenseDeclared) {
		// The declared license, which can be all over the place.
		return []string{pkg.PackageLicenseDeclared}
	}
	return []string{}
}

func spdxExtractCopyrights(pkg *spdx.Package) []string {
	if pkg == nil {
		return nil
	}
	if spdxIsValidString(pkg.PackageCopyrightText) {
		return []string{pkg.PackageCopyrightText}
	}
	return nil
}

func spdxExtractLocations(pkg *spdx.Package) []string {
	if pkg == nil {
		return nil
	}
	locs := []string{}
	if spdxIsValidString(pkg.PackageFileName) {
		locs = append(locs, pkg.PackageFileName)
	}
	if spdxIsValidString(pkg.PackageDownloadLocation) {
		locs = append(locs, pkg.PackageDownloadLocation)
	}
	return locs
}

func spdxExtractIdentifiers(pkg *spdx.Package) []sbommodel.Identifier {
	if pkg == nil {
		return nil
	}
	ident := []sbommodel.Identifier{}
	if spdxIsValidString(string(pkg.PackageSPDXIdentifier)) {
		ident = append(ident, sbommodel.Identifier{
			Type:  sbommodel.IdentifierTypeBomRef,
			Value: string(pkg.PackageSPDXIdentifier),
		})
	}
	for _, extId := range pkg.PackageExternalReferences {
		if spdxIsValidString(extId.Locator) {
			if extId.RefType == "purl" {
				ident = append(ident, sbommodel.Identifier{
					Type:  sbommodel.IdentifierTypePurl,
					Value: extId.Locator,
				})
				continue
			}
			if strings.Contains(extId.RefType, "cpe") {
				ident = append(ident, sbommodel.Identifier{
					Type:  sbommodel.IdentifierTypeCPE,
					Value: extId.Locator,
				})
				continue
			}
			idType := sbommodel.IdentifierType(extId.RefType)
			if idType != "" {
				ident = append(ident, sbommodel.Identifier{
					Type:  idType,
					Value: extId.Locator,
				})
			}
		}
	}
	for _, h := range pkg.PackageChecksums {
		if spdxIsValidString(h.Value) && spdxIsValidString(string(h.Algorithm)) {
			ident = append(ident, sbommodel.Identifier{
				Type:  sbommodel.IdentifierType(strings.ToLower(string(h.Algorithm))),
				Value: h.Value,
			})
		}
	}
	return ident
}

func spdxIsValidString(s string) bool {
	return s != "" && s != "NOASSERTION" && s != "NONE"
}

func fillSpdxDependencies(pkg *sbommodel.SbomPackageInfo, spdxDoc *spdx.Document) *sbommodel.SbomPackageDependencies {
	if pkg == nil || spdxDoc == nil {
		return nil
	}
	deps := make([][]sbommodel.Identifier, 0)

	// Extract sbom references to speed up matching.
	sbomRefs := sbommodel.JustSbomRefs(pkg.Identifiers)
	for _, r := range spdxDoc.Relationships {
		if r == nil {
			continue
		}
		for _, id := range sbomRefs {
			// This needs improvement to look into external documents.
			// If that happens, this will need to move to goroutines.
			if string(r.RefA.ElementRefID) == id.Value &&
				spdxIsValidString(string(r.RefB.ElementRefID)) &&
				(r.Relationship == "DEPENDS_ON" ||
					r.Relationship == "RUNTIME_DEPENDENCY_OF" ||
					r.Relationship == "BUILD_DEPENDENCY_OF" ||
					r.Relationship == "DEV_DEPENDENCY_OF" ||
					r.Relationship == "OPTIONAL_DEPENDENCY_OF" ||
					r.Relationship == "TEST_DEPENDENCY_OF" ||
					r.Relationship == "PROVIDED_DEPENDENCY_OF" ||
					r.Relationship == "CONTAINS") {
				// Find the package that matches RefB
				deps = append(deps, []sbommodel.Identifier{
					{
						Type:  sbommodel.IdentifierTypeBomRef,
						Value: string(r.RefB.ElementRefID),
					},
				})
			}
		}
	}
	return &sbommodel.SbomPackageDependencies{
		SbomPackageInfo: *pkg,
		Dependencies:    deps,
	}
}
