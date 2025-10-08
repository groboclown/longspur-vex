package sbommodel

import (
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
)

// RawPackage contains basic information loaded from the SBOM.
// It must be normalized through the NewSbomPackageInfo function to create a SbomPackageInfo.
type RawPackage struct {
	// Human-readable name representation of the package.
	Name string
	// Common version expression for the package.
	// Optional, as some SBOM tools may not be able to identify the version.
	Version *string
	// Package URL (purl) for the package.
	// While some SBOM formats may not include a purl, it can often be constructed
	// from other fields such as name, version, and namespace.
	// Required, as it provides a standardized way to identify packages.
	Purl packageurl.PackageURL
	// Methods used by the SBOM tool to identify the package.
	// Helps to match the package across different SBOM formats and files, and
	// within the SBOM itself.
	Identifiers []Identifier
	// Licenses associated with the package.
	// Should be in SPDX format where possible.
	// Optional, as some SBOM tools or packages may not provide license information.
	// Note that this could be much richer, but for simplicity, we just use a list of strings.
	Licenses []string
	// Copyright statements for the package, if available.
	Copyright []string
	// Locations where the package was found, e.g. file paths or URLs.
	// Optional, as some SBOM tools may not provide location information,
	// or it may not apply.  Mostly used by inspections of container images or
	// distributed archives.
	Locations []string
}

func NewSbomPackageInfo(pkg *RawPackage, source SbomPackageSource, path string) (*SbomPackageInfo, error) {
	if pkg == nil {
		return nil, nil
	}
	purl := ClonePurl(pkg.Purl)
	if err := purl.Normalize(); err != nil {
		return nil, err
	}
	return &SbomPackageInfo{
		Name:        normalizeString(pkg.Name),
		Version:     normalizeStrPtr(pkg.Version),
		Purl:        purl,
		Identifiers: NormalizeIdentifiers(pkg.Identifiers),
		Licenses:    normalizeStringSlice(pkg.Licenses),
		Copyright:   normalizeStringSlice(pkg.Copyright),
		Locations:   normalizeStringSlice(pkg.Locations),
		Source:      source,
		SourcePath:  path,
	}, nil
}

func normalizeStringSlice(input []string) []string {
	uniqueMap := make(map[string]any)
	for _, str := range input {
		trimmed := strings.TrimSpace(str)
		if trimmed != "" {
			uniqueMap[trimmed] = nil
		}
	}
	uniqueList := make([]string, 0, len(uniqueMap))
	for str := range uniqueMap {
		uniqueList = append(uniqueList, str)
	}
	sort.Strings(uniqueList)
	return uniqueList
}

func normalizeString(input string) string {
	return strings.TrimSpace(input)
}

func normalizeStrPtr(input *string) *string {
	if input == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*input)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// Clone creates a deep copy of the SbomPackageInfo.
func (p *SbomPackageInfo) Clone() *SbomPackageInfo {
	if p == nil {
		return nil
	}
	return &SbomPackageInfo{
		Name:        p.Name,
		Version:     p.Version,
		Purl:        ClonePurl(p.Purl),
		Identifiers: append([]Identifier{}, p.Identifiers...),
		Licenses:    append([]string{}, p.Licenses...),
		Copyright:   append([]string{}, p.Copyright...),
		Locations:   append([]string{}, p.Locations...),
		Source:      p.Source,
		SourcePath:  p.SourcePath,
	}
}

// Join merges two SbomPackageInfo into a new copy.
// If the Purl, Name or Version do not match, it returns nil.
// Note that this expects the package info to be normalized
// (created through the NewSbomPackageInfo function).
func (p *SbomPackageInfo) Join(o *SbomPackageInfo) *SbomPackageInfo {
	if p == nil {
		return o.Clone()
	}
	if o == nil {
		return p.Clone()
	}

	if p.Purl.String() != o.Purl.String() ||
		p.Name != o.Name ||
		(p.Version == nil && o.Version != nil) ||
		(p.Version != nil && o.Version == nil) ||
		(p.Version != nil && o.Version != nil && *p.Version != *o.Version) {
		// Names or versions do not match; cannot merge.
		return nil
	}

	ret := p.Clone()
	// Merge causes the source to no longer be valid.
	ret.Source = nil
	ret.SourcePath = ""

	// Merge Identifiers
	{
		identifierMap := make(map[string]any)
		for _, id := range ret.Identifiers {
			identifierMap[id.String()] = nil
		}
		changed := false
		for _, id := range o.Identifiers {
			if _, exists := identifierMap[id.String()]; !exists {
				ret.Identifiers = append(ret.Identifiers, id)
				identifierMap[id.String()] = nil
				changed = true
			}
		}
		if changed {
			ret.Identifiers = NormalizeIdentifiers(ret.Identifiers)
		}
	}

	// Merge Licenses
	{
		licenseMap := make(map[string]any)
		for _, lic := range ret.Licenses {
			licenseMap[lic] = nil
		}
		changed := false
		for _, lic := range o.Licenses {
			if _, exists := licenseMap[lic]; !exists {
				ret.Licenses = append(ret.Licenses, lic)
				licenseMap[lic] = nil
				changed = true
			}
		}
		if changed {
			sort.Strings(ret.Licenses)
		}
	}

	// Merge Locations
	{
		locationMap := make(map[string]any)
		for _, loc := range ret.Locations {
			locationMap[loc] = nil
		}
		changed := false
		for _, loc := range o.Locations {
			if _, exists := locationMap[loc]; !exists {
				ret.Locations = append(ret.Locations, loc)
				locationMap[loc] = nil
				changed = true
			}
		}
		if changed {
			sort.Strings(ret.Locations)
		}
	}

	// Merge Copyright
	{
		copyrightMap := make(map[string]any)
		for _, c := range ret.Copyright {
			copyrightMap[c] = nil
		}
		changed := false
		for _, c := range o.Copyright {
			if _, exists := copyrightMap[c]; !exists {
				ret.Copyright = append(ret.Copyright, c)
				copyrightMap[c] = nil
				changed = true
			}
		}
		if changed {
			sort.Strings(ret.Copyright)
		}
	}

	return ret
}
