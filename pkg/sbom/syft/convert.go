package syft

import (
	"fmt"

	"github.com/anchore/syft/syft/sbom"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
)

func ConvertSyft(input *longspurio.RelResource, syftDoc *sbom.SBOM) (*sbommodel.ReadableSbom, error) {
	return nil, fmt.Errorf("not implemented") // TODO: implement
}
