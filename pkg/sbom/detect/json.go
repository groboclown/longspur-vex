/*
SPDX-License-Identifier: Apache-2.0
*/
package detect

import (
	"encoding/json"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

type SbomJsonFormat int

const (
	UnknownJsonFormat SbomJsonFormat = iota
	CycloneDXJsonFormat
	SpdxJsonFormat
	SyftJsonFormat
)

// DiscoverJsonFormat inspects the provided JSON data to determine if it is a known SBOM format.
func DiscoverJsonFormat(data []byte) SbomJsonFormat {
	var doc MetadataDoc
	if err := json.Unmarshal(data, &doc); err == nil {
		if doc.BOMFormat != nil && *doc.BOMFormat == cyclonedx.BOMFormat {
			return CycloneDXJsonFormat
		}
		if doc.SPDXVersion != nil && *doc.SPDXVersion != "" {
			return SpdxJsonFormat
		}
		if doc.Context != nil && strings.HasPrefix(*doc.Context, "https://spdx.org/") {
			return SpdxJsonFormat
		}
		if doc.Schema != nil && doc.Schema.URL != nil && strings.Contains(*doc.Schema.URL, "anchore/syft") {
			return SyftJsonFormat
		}
	}
	return UnknownJsonFormat
}

type MetadataDoc struct {
	Context     *string         `json:"@context,omitempty"`
	SPDXVersion *string         `json:"spdxVersion,omitempty"`
	BOMFormat   *string         `json:"bomFormat,omitempty"`
	Schema      *MetadataSchema `json:"schema,omitempty"`
}

type MetadataSchema struct {
	// From Syft
	Version *string `json:"version,omitempty"`
	URL     *string `json:"url,omitempty"`
}
