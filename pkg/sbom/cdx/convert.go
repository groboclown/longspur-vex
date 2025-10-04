package cdx

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/package-url/packageurl-go"
)

func ConvertCdx(input *longspurio.RelResource, cdxBom *cyclonedx.BOM) (*sbommodel.ReadableSbom, error) {
	errs := []error{}
	tree, err_list := parseCdxToDependencies(cdxBom)
	if err_list != nil {
		errs = append(errs, err_list...)
	}
	sbom, err := sbommodel.ConvertDependencyTree(input, tree)
	if err != nil {
		errs = append(errs, err)
	}
	if sbom == nil || len(errs) > 0 {
		return nil, sbommodel.NewSbomParseError(input.Path(), errs)
	}
	for _, pkg := range sbom.Packages {
		pkg.SourcePath = input.Path()
	}
	return sbom, nil
}

func parseCdxToDependencies(cdxBom *cyclonedx.BOM) ([]*sbommodel.SbomPackageDependencies, []error) {
	if cdxBom == nil || cdxBom.Components == nil {
		return nil, nil
	}
	errs := []error{}
	tree := make([]*sbommodel.SbomPackageDependencies, 0, len(*cdxBom.Components))

	for _, c := range *cdxBom.Components {
		pkg, err := convertCdxComponentToInfo(&c)
		if err != nil {
			errs = append(errs, err)
		} else {
			pkgDep := fillDependencies(pkg, cdxBom)
			if pkgDep != nil {
				tree = append(tree, pkgDep)
			}
		}
	}
	return tree, errs
}

func convertCdxComponentToInfo(c *cyclonedx.Component) (*sbommodel.SbomPackageInfo, error) {
	if c == nil || c.PackageURL == "" {
		// This only captures packages that have a purl.  Others tend to be things
		// like a file or an OS.
		// This is based on experimentation.  Other formats might show other things need
		// capturing.
		return nil, nil
	}
	purl, err := packageurl.FromString(c.PackageURL)
	if err != nil {
		return nil, err
	}
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + name
	}

	ident := []sbommodel.Identifier{}
	lics := []string{}
	cw := []string{}
	locs := []string{}
	if c.Licenses != nil {
		for _, l := range *c.Licenses {
			if l.License != nil && l.License.ID != "" {
				lics = append(lics, l.License.ID)
			} else if l.Expression != "" {
				lics = append(lics, l.Expression)
			}
		}
	}
	if c.Copyright != "" {
		cw = append(cw, c.Copyright)
	}
	// Locations not supported.

	// All the identifier places.
	if c.BOMRef != "" {
		ident = append(ident, sbommodel.Identifier{
			Type:  sbommodel.IdentifierTypeBomRef,
			Value: c.BOMRef,
		})
	}
	if c.CPE != "" {
		ident = append(ident, sbommodel.Identifier{
			Type:  sbommodel.IdentifierTypeCPE,
			Value: c.CPE,
		})
	}
	if c.PackageURL != "" {
		ident = append(ident, sbommodel.Identifier{
			Type:  sbommodel.IdentifierTypePurl,
			Value: c.PackageURL,
		})
	}
	if c.Hashes != nil {
		for _, h := range *c.Hashes {
			ident = append(ident, sbommodel.Identifier{
				Type:  sbommodel.IdentifierType(strings.ToLower(string(h.Algorithm))),
				Value: h.Value,
			})
		}
	}
	if c.PackageURL != "" {
		locs = append(locs, c.PackageURL)
	}

	return &sbommodel.SbomPackageInfo{
		Name:        name,
		Version:     &c.Version,
		Purl:        purl,
		Identifiers: ident,
		Licenses:    lics,
		Copyright:   cw,
		Locations:   locs,
		Source:      c,
	}, nil
}

// Look up the dependencies for the given package from the base BOM, and fill them in.
func fillDependencies(pkg *sbommodel.SbomPackageInfo, cdxBom *cyclonedx.BOM) *sbommodel.SbomPackageDependencies {
	if pkg == nil || cdxBom == nil {
		return nil
	}
	deps := [][]sbommodel.Identifier{}

	// Check the dependencies set first.
	// Because the dependency list can be large, extract out the bom-ref identifiers
	// to make the matching faster.
	sbomRefs := sbommodel.JustSbomRefs(pkg.Identifiers)
	if len(sbomRefs) > 0 && cdxBom.Dependencies != nil {
		for _, d := range *cdxBom.Dependencies {
			if d.Dependencies != nil && matchesAnySbomRef(d.Ref, sbomRefs) {
				for _, dep := range *d.Dependencies {
					deps = append(deps, []sbommodel.Identifier{
						{
							Type:  sbommodel.IdentifierTypeBomRef,
							Value: dep,
						},
					})
				}
			}
		}
	}

	// Compositions.  These also reuse the bom-ref identifier.
	// They generally don't relate to the package, but maybe?
	if len(sbomRefs) > 0 && cdxBom.Compositions != nil {
		for _, c := range *cdxBom.Compositions {
			if c.Dependencies != nil && matchesAnySbomRef(c.BOMRef, sbomRefs) {
				for _, dep := range *c.Dependencies {
					deps = append(deps, []sbommodel.Identifier{
						{
							Type:  sbommodel.IdentifierTypeBomRef,
							Value: string(dep),
						},
					})
				}
			}
		}
	}

	// Don't include 'task' or 'workflow'

	return &sbommodel.SbomPackageDependencies{
		SbomPackageInfo: *pkg,
		Dependencies:    deps,
	}
}

func matchesAnySbomRef(sbomRef string, idents []sbommodel.Identifier) bool {
	for _, id := range idents {
		if sbomRef == id.Value {
			return true
		}
	}
	return false
}
