package scan

import (
	"context"

	"github.com/groboclown/cve-longspur/cmd/longspur/cmd/config"
	"github.com/urfave/cli/v3"
)

// ScanBuilder constructs the 'scan' command for the CLI application.
func ScanBuilder(ctx *config.CliContext) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Description: "Scan SBOMs against CVEs, and include VEX documents in the analysis.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "Path to the scan configuration file.",
			},
		},
		Action: scanAction,
	}
}

func scanAction(context.Context, *cli.Command) error {
	// TODO needs to construct the ScanSettings.
	return nil
}
