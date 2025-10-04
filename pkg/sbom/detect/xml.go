/*
SPDX-License-Identifier: Apache-2.0
*/
package detect

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/rdf"
)

type SbomXmlFormat int

const (
	UnknownXmlFormat SbomXmlFormat = iota
	CycloneDXXmlFormat
	SpdxRdfFormat
)

// DiscoverXmlFormat inspects the provided XML data to determine if it is a known SBOM format.
// This is highly inefficient, as it means it's performing double parsing.
func DiscoverXmlFormat(data []byte) SbomXmlFormat {
	if _, err := rdf.Read(strings.NewReader(string(data))); err == nil {
		return SpdxRdfFormat
	}
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(strings.NewReader(string(data)), cyclonedx.BOMFileFormatXML).Decode(&cdxBOM)
	if err == nil && cdxBOM.Metadata != nil {
		return CycloneDXXmlFormat
	}
	return UnknownXmlFormat
}
