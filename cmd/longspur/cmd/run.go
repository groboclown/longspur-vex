/*
SPDX-License-Identifier: Apache-2.0
*/
package cmd

import (
	longspur "github.com/groboclown/cve-longspur"
	"github.com/groboclown/cve-longspur/cmd/longspur/cmd/config"
	"github.com/urfave/cli/v3"
)

// Run executes the CLI application.
func Run(args []string, ctx *config.CliContext, commands []config.CommandBuilder) int {
	cmds := make([]*cli.Command, 0, len(commands))
	for _, b := range commands {
		cmds = append(cmds, b(ctx))
	}
	app := &cli.Command{
		Name:        "longspur",
		Description: "Analyze your SBOMs and VEX statements against CVEs.",
		Commands:    cmds,
		Version:     "v" + longspur.Version(),
	}
	if err := app.Run(ctx.Context(), args); err != nil {
		ctx.UserWriter().Write([]byte(err.Error() + "\n"))
		return 1
	}
	return 0
}
