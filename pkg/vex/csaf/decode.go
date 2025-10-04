package csaf

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/package-url/packageurl-go"
)

func DecodeJson(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	fh, err := input.Open()
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to open document: %w", err)
	}
	defer fh.Close()
	csafDoc := &csaf.CSAF{}
	err = json.NewDecoder(fh).Decode(csafDoc)
	if err != nil {
		return nil, fmt.Errorf("csaf: failed to decode document: %w", err)
	}

	return ConvertCsaf(purl, input, csafDoc)
}
