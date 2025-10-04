/*
SPDX-License-Identifier: Apache-2.0
*/
package scalibr

import (
	"io"
	"os"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/fs"
)

func NewScanInputReader(root string, filename string, data io.Reader) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		FS:     fs.DirFS(root),
		Path:   filename,
		Root:   root,
		Info:   nil,
		Reader: data,
	}
}

// NewScanInputFile creates a ScanInput for the given file on disk.
// This returns a new, opened file reader that must be closed by the caller.
func NewScanInputFile(root string, filename string) (*filesystem.ScanInput, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	inp, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return &filesystem.ScanInput{
		FS:     fs.DirFS(root),
		Path:   filename,
		Root:   root,
		Info:   info,
		Reader: inp,
	}, nil
}

func NewScanInputBytes(root string, filename string, data []byte) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		FS:     fs.DirFS(root),
		Path:   filename,
		Root:   root,
		Info:   nil,
		Reader: strings.NewReader(string(data)),
	}
}

// RenameScanInputPath returns a new ScanInput with the same properties as the input but different path.
func RenameScanInputPath(input *filesystem.ScanInput, newPath string) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		FS:     input.FS,
		Path:   newPath,
		Root:   input.Root,
		Info:   input.Info,
		Reader: input.Reader,
	}
}

// RenameScanInputPath returns a new ScanInput with the same properties as the input but different reader.
// It's up to the caller to close the original reader (if needed).
func SwapScanInputReader(input *filesystem.ScanInput, reader io.Reader) *filesystem.ScanInput {
	return &filesystem.ScanInput{
		FS:     input.FS,
		Path:   input.Path,
		Root:   input.Root,
		Info:   input.Info,
		Reader: reader,
	}
}
