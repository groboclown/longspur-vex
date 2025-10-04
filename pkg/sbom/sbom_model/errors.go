package sbommodel

import "fmt"

// SbomParseError represents an error that occurred while parsing or converting an SBOM.
type SbomParseError struct {
	// The source of the SBOM, e.g. file path or URL.
	Source string
	// The errors that came from the parsing or conversion of the SBOM.
	Errs []error
}

func (e *SbomParseError) Error() string {
	return fmt.Sprintf("%s: %v", e.Source, e.Errs)
}

// NewSbomParseError creates a new SbomParseError with the given source and errors.
func NewSbomParseError(source string, errs []error) *SbomParseError {
	return &SbomParseError{
		Source: source,
		Errs:   errs,
	}
}
