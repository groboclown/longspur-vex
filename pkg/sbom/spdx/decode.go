/*
SPDX-License-Identifier: Apache-2.0
*/
package spdx

import (
	"context"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"
)

// See https://github.com/spdx/spdx-spec/blob/develop/docs/serializations.md
// for details into the different supported formats.

// JsonDecodeReader decodes a SPDX BOM from JSON format.
func JsonDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	doc, err := json.Read(input.Reader())
	if err != nil {
		return nil, err
	}
	return ConvertSpdx(input, doc)
}

// TagValueDecodeReader decodes a SPDX BOM from SPDX tag value format.
func TagValueDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	doc, err := tagvalue.Read(input.Reader())
	if err != nil {
		return nil, err
	}
	return ConvertSpdx(input, doc)
}

// YamlDecodeReader decodes a SPDX BOM from YAML format.
func YamlDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	doc, err := yaml.Read(input.Reader())
	if err != nil {
		return nil, err
	}
	return ConvertSpdx(input, doc)
}

// RdfXmlDecodeReader decodes a SPDX BOM from RDF XML format.
func RdfXmlDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	doc, err := rdf.Read(input.Reader())
	if err != nil {
		return nil, err
	}
	return ConvertSpdx(input, doc)
}
