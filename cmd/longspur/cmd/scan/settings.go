package scan

// ScanSettings holds configuration options for the scan command.
type ScanSettings struct {
	Sbom []SbomScan `json:"sboms,omitempty"`
}

type SbomScan struct {
	File string  `json:"file,omitempty"`
	Url  string  `json:"url,omitempty"`
	Type string  `json:"type,omitempty"` // e.g., "spdx", "cyclonedx"
	Use  SbomUse `json:"use,omitempty"`  // e.g., "declaration", "discovery"
}

type SbomUse string

const (
	SbomUseDeclaration SbomUse = "declaration" // Declares the packages used.
	SbomUseDiscovery   SbomUse = "discovery"   // Contains packages discovered, has some level of inaccuracy.
)
