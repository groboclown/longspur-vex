package openvex

import (
	"context"
	"fmt"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
	vexmodel "github.com/groboclown/cve-longspur/pkg/vex/vex_model"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v3"
)

// Unfortunately, the openvex module only works on local files.
// So most of this is cut-and-paste from:
// https://raw.githubusercontent.com/openvex/go-vex/refs/heads/main/pkg/vex/functions_files.go
//   Copyright 2023 The OpenVEX Authors
//   SPDX-License-Identifier: Apache-2.0
// On top of that, the compatibility loaders are hidden behind the
// Open function.

// So, most of that Open function is moved into the `detect` package.

func ParseJson(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	data, err := input.ReadAll()
	if err != nil {
		return nil, err
	}
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, err
	}
	return ConvertOpenVex(purl, input, doc)
}

func ParseYaml(ctx context.Context, purl packageurl.PackageURL, input *longspurio.RelResource) (*vexmodel.VEX, error) {
	data, err := input.ReadAll()
	if err != nil {
		return nil, err
	}

	// In-line from vex.ParseYaml
	vexDoc := vex.New()
	if err := yaml.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}

	return ConvertOpenVex(purl, input, &vexDoc)
}
