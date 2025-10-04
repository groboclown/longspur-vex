/*
SPDX-License-Identifier: Apache-2.0
*/
package sbommodel

import (
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	"github.com/package-url/packageurl-go"
)

// Sbom represents a Software Bill of Materials (SBOM).
// Another generic type that contains information from various SBOM formats.
// While SBOM formats can contain many different kinds of information, including
// exploitability information, this focuses on the included dependency hierarchy.
type Sbom struct {
	// The source of the SBOM, e.g. file path or URL.
	Source string
	// The packages contained in the SBOM.
	Packages []*SbomPackage
	// The top-level packages in the SBOM (i.e. those without parents).
	RootPackages []packageurl.PackageURL
}

// ReadableSbom allows for accessing the original SBOM along with the parsed model.
type ReadableSbom struct {
	Sbom
	Reader longspurio.OpenReader

	// TODO add discovered format?
}

// SbomPackage represents a software package or component in an SBOM.
type SbomPackageInfo struct {
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

	// The structure which populated this package information.
	// This can be used to access format-specific fields not represented in this generic model.
	// The actual type will depend on the SBOM format and the tool used to generate it.
	// For example, it could be a CycloneDX component, SPDX package, etc.
	// This field is optional and may be nil if the original structure is not needed.
	Source     SbomPackageSource
	SourcePath string // The "Source" from the parent Sbom.
}

type SbomPackageSource any

// SbomPackageDependencies represents a package along with its direct dependencies.
// If an SBOM format supports dependency information, then it MUST contain directly
// mappable (100% match) identifiers to the dependencies.
type SbomPackageDependencies struct {
	SbomPackageInfo
	// Direct dependencies of this package.
	// Each dependency is represented as a list of identifiers to allow for
	// multiple ways to identify the dependency package.
	// If not provided, the package is assumed to have no dependencies.
	Dependencies [][]Identifier
}

type SbomPackage struct {
	SbomPackageInfo

	// Parent packages that directly depend on this package.
	Parents []*SbomPackage

	// Child packages that this package directly depends on.
	Dependencies []*SbomPackage
}

// Identifier represents a generic identifier for a package, such as CPE, hash.
type Identifier struct {
	// The type of identifier, e.g. "cpe", "purl", "sha1", "layer-id", "sha256".
	// See the constants below for common types.  Note that this Type field
	// can take on other values as well.
	Type  IdentifierType
	Value string
}

type IdentifierType string

const (
	IdentifierTypeCPE     IdentifierType = "cpe"
	IdentifierTypePurl    IdentifierType = "purl"
	IdentifierTypeSha1    IdentifierType = "sha-1"
	IdentifierTypeLayerId IdentifierType = "layer-id"
	IdentifierTypeSha256  IdentifierType = "sha-256"
	IdentifierTypeBomRef  IdentifierType = "bom-ref"
)
