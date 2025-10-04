package openvex

import (
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

func ConvertOpenVex(purl packageurl.PackageURL, input *longspurio.RelResource, doc *vex.VEX) (*vexmodel.VEX, error) {
	statements := []*vexmodel.VexStatement{}

	for _, stmt := range doc.Statements {
		statements = append(statements, &vexmodel.VexStatement{
			Owner:      purl,
			Statement:  &stmt,
			Source:     &stmt,
			SourcePath: input.Path(),
		})
	}

	return &vexmodel.VEX{
		Owner:      purl,
		Statements: statements,
	}, nil
}
