package sbommodel

import "strings"

// IsVersionUnknown returns true if the version string is considered "unknown".
func (s *SbomPackageInfo) IsVersionUnknown() bool {
	return isVersionUnknown(s.Version)
}

func isVersionUnknown(version *string) bool {
	if version == nil {
		return false
	}
	v := *version
	v = strings.TrimSpace(v)
	v = strings.ToLower(v)
	_, exists := unknownValues[v]
	return exists
}

var unknownValues = map[string]any{}

func init() {
	unknownList := []string{
		// A heuristic list of common "unknown" version strings.
		"", "unknown", "none", "n/a", "na", "not applicable", "not available",
		"unspecified", "undefined", "latest", "current",
		// Not using "0.0.0", "0"
	}
	for _, uv := range unknownList {
		unknownValues[uv] = nil
	}
}
