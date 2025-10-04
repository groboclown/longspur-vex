package syft

import (
	"context"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
)

func JsonDecodeReader(ctx context.Context, input *longspurio.RelResource) (*sbommodel.ReadableSbom, error) {
	decoder := syftjson.NewFormatDecoder()
	inp := input.Reader()
	defer inp.Close()
	bom, _, _, err := decoder.Decode(inp)
	if err != nil {
		return nil, err
	}
	return ConvertSyft(input, bom)
}
