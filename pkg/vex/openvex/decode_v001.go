package openvex

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/package-url/packageurl-go"
)

// ParseOpenVex001 parses an OpenVEX v0.0.1 document from the given resource.
// Reference https://github.com/openvex/go-vex/blob/main/pkg/vex/compat.go
//
//	Copyright 2023 The OpenVEX Authors
//	SPDX-License-Identifier: Apache-2.0
func ParseOpenVex001(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	data, err := input.ReadAll()
	if err != nil {
		return nil, err
	}
	doc := &Vex001{}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf(
			"decoding OpenVEX v0.0.1 in compatibility mode: %w", err,
		)
	}
	return ConvertOpenVex001(purl, input, doc)
}

type Vex001 struct {
	Context    string          `json:"@context"`
	ID         string          `json:"@id"`
	Author     string          `json:"author"`
	AuthorRole string          `json:"role"`
	Timestamp  *time.Time      `json:"timestamp"`
	Version    string          `json:"version"`
	Tooling    string          `json:"tooling,omitempty"`
	Supplier   string          `json:"supplier,omitempty"`
	Statements []*Statement001 `json:"statements"`
}

type Statement001 struct {
	Vulnerability            string     `json:"vulnerability,omitempty"`
	VulnDescription          string     `json:"vuln_description,omitempty"`
	Timestamp                *time.Time `json:"timestamp,omitempty"`
	Products                 []string   `json:"products,omitempty"`
	Subcomponents            []string   `json:"subcomponents,omitempty"`
	Status                   string     `json:"status"`
	StatusNotes              string     `json:"status_notes,omitempty"`
	Justification            string     `json:"justification,omitempty"`
	ImpactStatement          string     `json:"impact_statement,omitempty"`
	ActionStatement          string     `json:"action_statement,omitempty"`
	ActionStatementTimestamp *time.Time `json:"action_statement_timestamp,omitempty"`
}
