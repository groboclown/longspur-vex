package vexmodel

import (
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// VEX represents a Vulnerability Exploitability eXchange document, which contains
// but only the parts that this tool cares about.
type VEX struct {
	Owner      packageurl.PackageURL
	Statements []*VexStatement
}

// VexStatement represents a single statement within a VEX document.
// This is almost 1-for-1 with the OpenVex statement type.
type VexStatement struct {
	Statement *vex.Statement

	// For the purposes of this program, though, it requires knowledge of the owning source.
	// When determining whether a CVE affects a product, it depends on whether the dependency that
	// uses the CVE affected dependency has an attestation.
	// In the case of reporting through a transient dependency, this owner points to the
	// project that performed the analysis in the statement, so that proper lineage of
	// affected products can be determined.
	Owner packageurl.PackageURL

	// The structure which populated this package information.
	// This can be used to access format-specific fields not represented in this generic model.
	// The actual type will depend on the VEX document format and the tool used to generate it.
	Source     VexStatementSource
	SourcePath string // The "Source" from the parent VEX document.
}

type VexStatementSource any
