/*
SPDX-License-Identifier: Apache-2.0
*/
package detect

import (
	"strings"

	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"
)

type SbomGeneralFormat int

const (
	UnknownGeneralFormat SbomGeneralFormat = iota
	SpdxYamlFormat
	SpdxTagValueFormat
)

// DiscoverGeneralFormat inspects the provided text data to determine if it is a known SBOM format.
func DiscoverGeneralFormat(data []byte) SbomGeneralFormat {
	// Try the different formats, and see which fails.
	// The yaml is a superset of the tag-value format, so try that second.
	if _, err := tagvalue.Read(strings.NewReader(string(data))); err == nil {
		return SpdxTagValueFormat
	}
	if _, err := yaml.Read(strings.NewReader(string(data))); err == nil {
		return SpdxYamlFormat
	}
	return UnknownGeneralFormat
}
