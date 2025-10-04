package openvex

import (
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// ParseOpenVex001 parses an OpenVEX v0.0.1 document from the given resource.
// Reference https://github.com/openvex/go-vex/blob/main/pkg/vex/compat.go
//
//	Copyright 2023 The OpenVEX Authors
//	SPDX-License-Identifier: Apache-2.0
func ConvertOpenVex001(purl packageurl.PackageURL, input *longspurio.RelResource, doc *Vex001) (*vexmodel.VEX, error) {
	statements := []*vexmodel.VexStatement{}

	// Transcode the statements
	for _, oldStmt := range doc.Statements {
		newStmt := &vex.Statement{}
		newStmt.Status = vex.Status(oldStmt.Status)
		newStmt.StatusNotes = oldStmt.StatusNotes
		newStmt.ActionStatement = oldStmt.ActionStatement
		newStmt.ActionStatementTimestamp = oldStmt.ActionStatementTimestamp
		newStmt.Justification = vex.Justification(oldStmt.Justification)
		newStmt.ImpactStatement = oldStmt.ImpactStatement
		newStmt.Timestamp = oldStmt.Timestamp

		// Add the vulnerability
		newStmt.Vulnerability = vex.Vulnerability{
			Name:        vex.VulnerabilityID(oldStmt.Vulnerability),
			Description: oldStmt.VulnDescription,
		}

		// Transcode the products from the old statement
		for _, productID := range oldStmt.Products {
			newProduct := vex.Product{
				Component: vex.Component{
					ID: productID,
				},
				Subcomponents: []vex.Subcomponent{},
			}

			for _, sc := range oldStmt.Subcomponents {
				if sc == "" {
					continue
				}
				newProduct.Subcomponents = append(newProduct.Subcomponents, vex.Subcomponent{
					Component: vex.Component{
						ID: sc,
					},
				})
			}
			newStmt.Products = append(newStmt.Products, newProduct)
		}
		statements = append(statements, &vexmodel.VexStatement{
			Owner:      purl,
			Statement:  newStmt,
			Source:     oldStmt,
			SourcePath: input.Path(),
		})
	}

	return &vexmodel.VEX{
		Owner:      purl,
		Statements: statements,
	}, nil
}
