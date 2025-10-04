package cdx

import (
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

// Example:
//   https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json

func ConvertCdx(purl packageurl.PackageURL, input *longspurio.RelResource, doc *cyclonedx.BOM) (*vexmodel.VEX, error) {
	statements := []*vexmodel.VexStatement{}
	if doc.Vulnerabilities == nil || len(*doc.Vulnerabilities) == 0 {
		return &vexmodel.VEX{
			Statements: statements,
		}, nil
	}
	for _, v := range *doc.Vulnerabilities {
		statement := ConvertCdxVulnerability(purl, &v, input)
		if statement != nil {
			statements = append(statements, statement)
		}
	}
	return &vexmodel.VEX{
		Statements: statements,
	}, nil
}

func ConvertCdxVulnerability(purl packageurl.PackageURL, v *cyclonedx.Vulnerability, input *longspurio.RelResource) *vexmodel.VexStatement {
	// If this doesn't contain an analysis, then it's just a CVE description.
	if v == nil || v.Analysis == nil || v.Affects == nil {
		return nil
	}

	products := []vex.Product{}
	for _, r := range *v.Affects {
		// FIXME
		// Product details MUST specify what Status applies to.
		// Product details MUST include [product_id] and MAY include [subcomponent_id].
		// Generally, the "ref" in the Affects is an URN, which should contain a Purl.
		p_l := ConvertCdxProduct(r)
		for _, p := range p_l {
			products = append(products, *p)
		}
	}

	return &vexmodel.VexStatement{
		Statement: &vex.Statement{
			// ID is an optional identifier for the statement. It takes an IRI and must
			// be unique for each statement in the document.
			ID: v.BOMRef,

			Vulnerability: vex.Vulnerability{
				// FIXME
			},

			// Timestamp is the time at which the information expressed in the Statement
			// was known to be true.
			Timestamp: decodeDatetime(v.Published),

			// LastUpdated records the time when the statement last had a modification
			LastUpdated: decodeDatetime(v.Updated),

			Products: products,

			// A VEX statement MUST provide Status of the vulnerabilities with respect to the
			// products and components listed in the statement. Status MUST be one of the
			// Status const values, some of which have further options and requirements.
			Status: ConvertCdxStatus(v.Analysis.State),

			// [status_notes] MAY convey information about how [status] was determined
			// and MAY reference other VEX information.
			StatusNotes: v.Analysis.Detail,

			// For "not_affected" status, a VEX statement MUST include a status Justification
			// that further explains the status.
			Justification: ConvertCdxJustification(v.Analysis.Justification),

			// For "not_affected" status, a VEX statement MAY include an ImpactStatement
			// that contains a description why the vulnerability cannot be exploited.
			ImpactStatement: "",

			// For "affected" status, a VEX statement MUST include an ActionStatement that
			// SHOULD describe actions to remediate or mitigate [vul_id].
			ActionStatement:          ConvertCdxActionStatement(v.Analysis.Response),
			ActionStatementTimestamp: decodeDatetime(v.Updated),
		},
		Owner:      purl,
		Source:     v,
		SourcePath: input.Path(),
	}
}

func decodeDatetime(s string) *time.Time {
	r, err := time.Parse(time.RFC3339, s)
	if err != nil {
		r, err = time.Parse("2006-01-02T15:04:05Z", s)
		if err != nil {
			return nil
		}
	}
	return &r
}

func ConvertCdxStatus(s cyclonedx.ImpactAnalysisState) vex.Status {
	switch s {
	case cyclonedx.IASExploitable:
		return vex.StatusAffected
	case cyclonedx.IASFalsePositive:
		return vex.StatusNotAffected
	case cyclonedx.IASNotAffected:
		return vex.StatusNotAffected
	case cyclonedx.IASResolved:
		return vex.StatusFixed
	case cyclonedx.IASResolvedWithPedigree:
		return vex.StatusFixed
	case cyclonedx.IASInTriage:
		return vex.StatusUnderInvestigation
	default:
		return "unknown"
	}
}

func ConvertCdxJustification(j cyclonedx.ImpactAnalysisJustification) vex.Justification {
	switch j {
	case cyclonedx.IAJCodeNotPresent:
		return vex.VulnerableCodeNotPresent
	case cyclonedx.IAJCodeNotReachable:
		return vex.VulnerableCodeNotInExecutePath
	case cyclonedx.IAJRequiresConfiguration:
		return vex.VulnerableCodeCannotBeControlledByAdversary
	case cyclonedx.IAJRequiresDependency:
		return vex.VulnerableCodeCannotBeControlledByAdversary
	case cyclonedx.IAJRequiresEnvironment:
		return vex.VulnerableCodeCannotBeControlledByAdversary
	case cyclonedx.IAJProtectedByCompiler:
		return vex.InlineMitigationsAlreadyExist
	case cyclonedx.IAJProtectedAtRuntime:
		return vex.InlineMitigationsAlreadyExist
	case cyclonedx.IAJProtectedAtPerimeter:
		return vex.InlineMitigationsAlreadyExist
	case cyclonedx.IAJProtectedByMitigatingControl:
		return vex.InlineMitigationsAlreadyExist
	default:
		return "unknown"
	}
}

func ConvertCdxActionStatement(r *[]cyclonedx.ImpactAnalysisResponse) string {
	// OpenVex just uses a simple string.
	if r == nil || len(*r) == 0 {
		return ""
	}
	// Just concatenate all the responses together.
	rb := []rune{}
	first := true
	for _, resp := range *r {
		if first {
			first = false
		} else {
			rb = append(rb, '\n')
		}
		rb = append(rb, []rune(resp)...)
	}
	return string(rb)
}

func ConvertCdxProduct(r cyclonedx.Affects) []*vex.Product {
	if r.Ref == "" {
		return nil
	}
	if strings.HasPrefix(r.Ref, "pkg:") {
		purl, err := packageurl.FromString(r.Ref)
		if err != nil {
			return nil
		}
		return purlsForAllVersions(purl, r.Range)
	}
	if strings.HasPrefix(r.Ref, "urn:") {
		// URN is not a PURL, but may contain a PURL.
		// Example: urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar
		parts := strings.Index(r.Ref, "#pkg:")
		if parts < 0 {
			return nil
		}
		purl, err := packageurl.FromString(r.Ref[parts+1:])
		if err != nil {
			return nil
		}
		return purlsForAllVersions(purl, r.Range)
	}
	// Dunno
	// Would be awesome to add logging here for people to debug.
	// cpe?
	return nil
}

func purlsForAllVersions(purl packageurl.PackageURL, affects *[]cyclonedx.AffectedVersions) []*vex.Product {
	if affects == nil || len(*affects) == 0 {
		return []*vex.Product{
			{
				Component: vex.Component{
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: purl.String(),
					},
					// Ignore Supplier, ID, and Hashes.
				},
			},
		}
	}
	products := []*vex.Product{}
	for _, v := range *affects {
		if v.Version == "" {
			continue
		}
		p := packageurl.PackageURL{
			Type:       purl.Type,
			Namespace:  purl.Namespace,
			Name:       purl.Name,
			Version:    v.Version,
			Qualifiers: make([]packageurl.Qualifier, len(purl.Qualifiers)),
			Subpath:    purl.Subpath,
		}
		copy(p.Qualifiers, purl.Qualifiers)
		products = append(products, &vex.Product{
			Component: vex.Component{
				Identifiers: map[vex.IdentifierType]string{
					vex.PURL: p.String(),
				},
				// Ignore Supplier, ID, and Hashes.
			},
		})
		purl.Version = v.Version
	}
	return products
}
