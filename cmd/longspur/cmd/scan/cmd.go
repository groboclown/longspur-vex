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
		Action: func(c context.Context, cmd *cli.Command) error {
			return scanAction(c, ctx, cmd)
		},
	}
}

func scanAction(ctx context.Context, conf *config.CliContext, cmd *cli.Command) error {
	// TODO needs to construct the ScanSettings.
	return nil
}
