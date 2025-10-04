package cdx

import (
	"context"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/package-url/packageurl-go"
)

func ParseJson(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	var cdxBOM cyclonedx.BOM
	err := cyclonedx.NewBOMDecoder(input.Reader(), cyclonedx.BOMFileFormatJSON).Decode(&cdxBOM)
	if err != nil {
		return nil, err
	}
	return ConvertCdx(purl, input, &cdxBOM)
}
