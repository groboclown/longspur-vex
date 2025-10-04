/*
SPDX-License-Identifier: Apache-2.0
*/
package config

import (
	"context"
	"io"

	"github.com/urfave/cli/v3"
)

// CliContext contains the data necessary to construct CLI runners.
type CliContext struct {
	stdout io.Writer
	stderr io.Writer
	ctx    context.Context
}

// NewCliContext creates a new CLI setup with the given output writers.
func NewCliContext(stdout, stderr io.Writer, ctx context.Context) *CliContext {
	return &CliContext{
		stdout: stdout,
		stderr: stderr,
		ctx:    ctx,
	}
}

// ReportWriter returns the writer used for generating the final report.
func (c *CliContext) ReportWriter() io.Writer {
	return c.stdout
}

// UserWriter returns the writer used for user messages, such as progress and errors.
func (c *CliContext) UserWriter() io.Writer {
	return c.stderr
}

// Context returns the base context for CLI operations.
func (c *CliContext) Context() context.Context {
	return c.ctx
}

type CommandBuilder func(ctx *CliContext) *cli.Command
