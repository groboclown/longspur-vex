package ubuntu

import (
	"context"
	"encoding/json"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/package-url/packageurl-go"
)

func ParseJson(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	data, err := input.ReadAll()
	if err != nil {
		return nil, err
	}
	doc := &UbuntuVEX{}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, err
	}
	return ConvertUbuntu(purl, input, doc)
}
