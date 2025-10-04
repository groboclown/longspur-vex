/*
SPDX-License-Identifier: Apache-2.0
*/
package cdx

// Use the SCalibr libraries to join the SBOM into a unified format.
// Note that SCalibr uses filenames to determine how to parse the
// files, so this lies to the library based on the assumption that
// this code can determine the file type better than the file name.

import (
	"context"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
)

// JsonDecodeReader decodes a CycloneDX BOM from JSON format.
func JsonDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(input.Reader(), cyclonedx.BOMFileFormatJSON).Decode(&cdxBOM)
	if err != nil {
		return nil, err
	}
	return ConvertCdx(input, &cdxBOM)
}

// XmlDecodeReader decodes a CycloneDX BOM from XML format.
func XmlDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(input.Reader(), cyclonedx.BOMFileFormatXML).Decode(&cdxBOM)
	if err != nil {
		return nil, err
	}
	return ConvertCdx(input, &cdxBOM)
}
