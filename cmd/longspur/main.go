/*
SPDX-License-Identifier: Apache-2.0
*/
package main

import (
	"context"
	"os"

	"github.com/groboclown/cve-longspur/cmd/longspur/cmd"
	"github.com/groboclown/cve-longspur/cmd/longspur/cmd/config"
)

func main() {
	os.Exit(
		cmd.Run(
			os.Args,
			config.NewCliContext(os.Stdout, os.Stderr, context.Background()),
			[]config.CommandBuilder{},
		),
	)
}
