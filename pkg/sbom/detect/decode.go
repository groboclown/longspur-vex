/*
SPDX-License-Identifier: Apache-2.0
*/
package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	"github.com/groboclown/cve-longspur/pkg/sbom/cdx"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/groboclown/cve-longspur/pkg/sbom/spdx"
	"github.com/groboclown/cve-longspur/pkg/sbom/syft"
)

type Decoder func(context.Context, *longspurio.RelResource) (*sbommodel.ReadableSbom, error)

var ExtDecoders map[string]Decoder = map[string]Decoder{
	".cdx.json":     cdx.JsonDecodeReader,
	".cdx.xml":      cdx.XmlDecodeReader,
	".spdx.json":    spdx.JsonDecodeReader,
	".spdx":         spdx.TagValueDecodeReader,
	".spdx.yml":     spdx.YamlDecodeReader,
	".spdx.rdf":     spdx.RdfXmlDecodeReader,
	".spdx.rdf.xml": spdx.RdfXmlDecodeReader,
	".syft.json":    syft.JsonDecodeReader,
}

// DecodeSbomFilenameReader decodes an SBOM from the provided filename and reader, automatically detecting the format.
// This uses the filename as a hint to avoid unnecessary processing.
func DecodeSbomFilenameReader(
	ctx context.Context,
	resource *longspurio.RelResource,
) (*sbommodel.ReadableSbom, error) {
	for ext, decoder := range ExtDecoders {
		if strings.HasSuffix(resource.Path(), ext) {
			return decoder(ctx, resource)
		}
	}

	// Default to the long reader.
	return DecodeSbomReader(ctx, resource)
}

// DecodeSbomReader decodes an SBOM from the provided reader, automatically detecting the format.
func DecodeSbomReader(
	ctx context.Context,
	resource *longspurio.RelResource,
) (*sbommodel.ReadableSbom, error) {
	// 1. Determine file format (xml or json)
	//    a. if XML, assume CycloneDX, as that's the only one that supports XML.
	// 2. Process the data by reading it in memory, then use an intermediary struct that
	//    contains all the supported fields for detecting the format.
	// 3. Based on the detected format, call and return the appropriate decoder.

	// This could use a buffered reader and read bits at a time, but, in the end,
	// all the decoders need the full data in memory anyway, so just read it all
	// at once.
	data, err := resource.ReadAll()
	if err != nil {
		return unknownFormat(err)
	}

	var r *sbommodel.ReadableSbom = nil

	switch firstNonWhitespace(data) {
	case 0:
		return unknownFormat(fmt.Errorf("empty SBOM data"))
	case '<':
		// XML format
		r, err = decodeXml(ctx, resource, data)
	case '{', '[':
		// JSON format
		r, err = decodeJson(ctx, resource, data)
	default:
		// Evaluate later.
	}
	if err != nil {
		return unknownFormat(fmt.Errorf("unsupported format"))
	}
	if r == nil {
		// Could not be determined.
		r, err = decodeGeneral(ctx, resource, data)
	}
	if err != nil {
		return unknownFormat(fmt.Errorf("unsupported format"))
	}
	return r, nil
}

func decodeGeneral(
	ctx context.Context,
	resource *longspurio.RelResource,
	data []byte,
) (*sbommodel.ReadableSbom, error) {
	switch DiscoverGeneralFormat(data) {
	case SpdxTagValueFormat:
		return spdx.TagValueDecodeReader(ctx, resource)
	case SpdxYamlFormat:
		return spdx.YamlDecodeReader(ctx, resource)
	case UnknownGeneralFormat:
		fallthrough
	default:
		return nil, nil
	}
}

func decodeJson(
	ctx context.Context,
	resource *longspurio.RelResource,
	data []byte,
) (*sbommodel.ReadableSbom, error) {
	switch DiscoverJsonFormat(data) {
	case CycloneDXJsonFormat:
		return cdx.JsonDecodeReader(ctx, resource)
	case SpdxJsonFormat:
		return spdx.JsonDecodeReader(ctx, resource)
	case SyftJsonFormat:
		return syft.JsonDecodeReader(ctx, resource)
	case UnknownJsonFormat:
		fallthrough
	default:
		return nil, nil
	}
}

func decodeXml(
	ctx context.Context,
	resource *longspurio.RelResource,
	data []byte,
) (*sbommodel.ReadableSbom, error) {
	switch DiscoverXmlFormat(data) {
	case CycloneDXXmlFormat:
		return cdx.XmlDecodeReader(ctx, resource)
	case SpdxRdfFormat:
		return spdx.RdfXmlDecodeReader(ctx, resource)
	case UnknownXmlFormat:
		fallthrough
	default:
		return nil, nil
	}
}

func firstNonWhitespace(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			// Ignore whitespace.
			continue
		default:
			return b
		}
	}
	return 0
}

func unknownFormat(err error) (*sbommodel.ReadableSbom, error) {
	if err == nil {
		return nil, fmt.Errorf("unable to determine SBOM format")
	}
	return nil, fmt.Errorf("unable to determine SBOM format: %w", err)
}
