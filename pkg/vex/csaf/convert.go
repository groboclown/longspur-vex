package csaf

import (
	"fmt"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/csaf"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// Unfortunately, the openvex module only works on local files.
// So this is cut-and-paste from:
// https://raw.githubusercontent.com/openvex/go-vex/refs/heads/main/pkg/vex/functions_files.go
// which is Apache-2.0 licensed.

func ConvertCsaf(purl packageurl.PackageURL, input *longspurio.RelResource, csafDoc *csaf.CSAF) (*vexmodel.VEX, error) {
	productDict := map[string]string{}
	filterDict := map[string]string{}

	prods := csafDoc.ProductTree.ListProducts()
	for _, sp := range prods {
		// Check if we need to filter
		if len(filterDict) > 0 {
			foundID := false
			for _, i := range sp.IdentificationHelper {
				if _, ok := filterDict[i]; ok {
					foundID = true
					break
				}
			}
			_, ok := filterDict[sp.ID]
			if !foundID && !ok {
				continue
			}
		}

		for _, h := range sp.IdentificationHelper {
			productDict[sp.ID] = h
		}
	}

	// Create the vex doc
	statements := []*vexmodel.VexStatement{}

	// Cycle the CSAF vulns list and get those that apply
	for i := range csafDoc.Vulnerabilities {
		for status, docProducts := range csafDoc.Vulnerabilities[i].ProductStatus {
			for _, productID := range docProducts {
				if _, ok := productDict[productID]; ok {
					// Check we have a valid status
					if vex.StatusFromCSAF(status) == "" {
						return nil, fmt.Errorf("invalid status for product %s", productID)
					}

					// TODO search the threats struct for justification, etc
					just := ""
					for _, t := range csafDoc.Vulnerabilities[i].Threats {
						// Search the threats for a justification
						for _, p := range t.ProductIDs {
							if p == productID {
								just = t.Details
							}
						}
					}

					statements = append(statements, &vexmodel.VexStatement{
						Statement: &vex.Statement{
							Vulnerability:   vex.Vulnerability{Name: vex.VulnerabilityID(csafDoc.Vulnerabilities[i].CVE)},
							Status:          vex.StatusFromCSAF(status),
							Justification:   "", // Justifications are not machine readable in csaf, it seems
							ActionStatement: just,
							Products: []vex.Product{
								{
									Component: vex.Component{
										ID: productID,
									},
								},
							},
						},
						Owner:      purl,
						Source:     &csafDoc.Vulnerabilities[i],
						SourcePath: input.Path(),
					})
				}
			}
		}
	}

	return &vexmodel.VEX{
		Statements: statements,
	}, nil
}
