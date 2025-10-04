package detect

import (
	"context"
	"encoding/json"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	"github.com/groboclown/cve-longspur/pkg/vex/openvex"
	"github.com/groboclown/cve-longspur/pkg/vex/ubuntu"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/package-url/packageurl-go"
)

func DecodeJson(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	data, err := input.ReadAll()
	if err != nil {
		return nil, err
	}

	// Map the document to a generic JSON structure to infer the type.
	meta := &DocumentMetadata{}
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, err
	}
	if meta.Metadata != nil && meta.Metadata.Context != nil && *meta.Metadata.Context == "https://openvex.dev/ns/v0.2.0" {
		return ubuntu.ParseJson(ctx, purl, input)
	}
	if meta.Context != nil && (*meta.Context == "https://openvex.dev/ns/v0.0.1" ||
		*meta.Context == "https://openvex.dev/ns") {
		// This is an OpenVEX v0.0.1 document.
		return openvex.ParseOpenVex001(ctx, purl, input)
	}
	if meta.Context != nil && *meta.Context == "https://openvex.dev/ns/v0.2.0" {
		// This is an OpenVEX v0.2.0 document.
		return openvex.ParseJson(ctx, purl, input)
	}
	if meta.Document != nil && meta.Document.Category == "csaf_vex" {
		// This is a CSAF VEX document.
		return openvex.ParseJson(ctx, purl, input)
	}

	// Unsupported or not a vex.
	return nil, nil
}

// DocumentMetadata contains generic structures to infer the document type from the JSON document.
type DocumentMetadata struct {
	Document    *VexDoc         `json:"document"`
	Context     *string         `json:"@context"`
	Metadata    *SimpleMetadata `json:"metadata"`
	BomFormat   *string         `json:"bomFormat"`
	SpecVersion *string         `json:"specVersion"`
}

type VexDoc struct {
	Category    string `json:"category"`
	CsafVersion string `json:"csaf_version"`
}

type SimpleMetadata struct {
	Context *string `json:"@context"`
}
