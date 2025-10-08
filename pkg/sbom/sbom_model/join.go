package sbommodel

// JoinSboms combines SBOMs into a single collection.
// Declaration SBOMs come from sources that explicitly declare the dependencies, such as
// from a lock file.
// Discovery SBOMs come from sources that inspect the artifact to find dependencies, such
// as from scanning a container image or filesystem.
// The discovery SBOMs are used only to detect dependencies not found in the declaration SBOMs.
func JoinSboms(
	declarationSboms []*Sbom,
	discoverySboms []*Sbom,
) []*Sbom {
	// Algorithm: Collect all distinct packages from the declaration SBOMs.
	// Then, for each discovery SBOM, add any packages not already present.
	packageMap := make(map[string]*SbomPackageInfo)
	names := make(map[string]any)
	nameVersions := make(map[string]any)
	for _, sbom := range declarationSboms {
		for _, pkg := range sbom.Packages {
			if val, exists := packageMap[pkg.Purl.String()]; exists {
				// Merge information if the package already exists.
				if merged := val.Join(&pkg.SbomPackageInfo); merged == nil {
					// FIXME log warning about inability to merge
				} else {
					// Replace the original with the joined version.
					packageMap[pkg.Purl.String()] = val
				}
				continue
			}

			packageMap[pkg.Purl.String()] = pkg.SbomPackageInfo.Clone()
			names[pkg.Name] = nil
			if pkg.Version != nil && *pkg.Version != "" {
				nameVersions[pkg.Name+"@"+*pkg.Version] = nil
			}
		}
	}

	for _, sbom := range discoverySboms {
		for _, pkg := range sbom.Packages {
			if val, exists := packageMap[pkg.Purl.String()]; exists {
				// Merge information if the package already exists.
				// As this is an exact match in a purl, the discovery is mergeable.
				if merged := val.Join(&pkg.SbomPackageInfo); merged == nil {
					// FIXME log warning about inability to merge
				} else {
					// Replace the original with the joined version.
					packageMap[pkg.Purl.String()] = val
				}
				continue
			}

			// Check if the name+version already exists.
			if pkg.Version != nil && *pkg.Version != "" {
				if _, nameVersionExists := nameVersions[pkg.Name+"@"+*pkg.Version]; nameVersionExists {
					continue
				}

				// In some cases, the version is listed as an unknown value.
				if pkg.IsVersionUnknown() {
					// If the version is unknown, we can only check by name.
					if _, nameExists := names[pkg.Name]; nameExists {
						continue
					}
				}

				// Otherwise, add the package.
				packageMap[pkg.Purl.String()] = &pkg.SbomPackageInfo
				names[pkg.Name] = nil
				nameVersions[pkg.Name+"@"+*pkg.Version] = nil
				continue
			}

			// No version, so just check by name.
			if _, nameExists := names[pkg.Name]; nameExists {
				continue
			}

			// Otherwise, add the package.
			packageMap[pkg.Purl.String()] = &pkg.SbomPackageInfo
			names[pkg.Name] = nil
		}
	}

	return nil
}
