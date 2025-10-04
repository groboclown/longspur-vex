package scanmodel

import "fmt"

// ScanError represents an error that occurred while scanning packages.
type ScanError struct {
	// The source of the SBOM, e.g. file path or URL.
	Source string
	// The errors that came from the parsing or conversion of the SBOM.
	Errs []error
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("%s: %v", e.Source, e.Errs)
}

// NewScanError creates a new ScanError with the given source and errors.
func NewScanError(source string, errs []error) *ScanError {
	return &ScanError{
		Source: source,
		Errs:   errs,
	}
}
