package scan

// ScanSettings holds configuration options for the scan command.
type ScanSettings struct {
	Sbom []SbomScan `json:"sboms,omitempty" yaml:"sboms,omitempty"`
}

type SbomScan struct {
	File string  `json:"file,omitempty" yaml:"file,omitempty"` // Local file path
	Url  string  `json:"url,omitempty" yaml:"url,omitempty"`   // Remote URL
	Type string  `json:"type,omitempty" yaml:"type,omitempty"` // e.g., "spdx", "cyclonedx"
	Use  SbomUse `json:"use,omitempty" yaml:"use,omitempty"`   // e.g., "declaration", "discovery"
}

type SbomUse string

const (
	SbomUseDeclaration SbomUse = "declaration" // Declares the packages used.
	SbomUseDiscovery   SbomUse = "discovery"   // Contains packages discovered, has some level of inaccuracy.
)
