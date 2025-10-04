/*
SPDX-License-Identifier: Apache-2.0
*/
package longspurio

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
)

// OpenReader is an interface for types that can open a resource for reading.
type OpenReader interface {
	// Open opens the resource for reading.
	// Caller is responsible for closing the reader.
	// If the open fails, an error is returned, and the reader is nil.
	Open() (io.ReadCloser, error)
}

// FileOpener is an Opener that opens a file from the filesystem.
type FileOpener string

// NewFileOpener creates a new FileOpener for the given file path.
func NewFileOpener(path string) FileOpener {
	return FileOpener(path)
}

func (f FileOpener) Open() (io.ReadCloser, error) {
	r, e := os.Open(string(f))
	if e != nil {
		// Just to be really, really sure.
		_ = r.Close()
		return nil, e
	}
	return r, nil
}

// HttpUrlOpener is an Opener that opens a resource from an HTTP URL.
// It only supports HTTP GET requests, and does not support authentication.
// It will return ErrNotExist on an error response.
// As this uses the default HTTP client, it will use the environment's proxy settings,
// and follow redirects.
type HttpUrlOpener string

// NewHttpUrlOpener creates a new HttpUrlOpener for the given URL.
func NewHttpUrlOpener(url string) HttpUrlOpener {
	return HttpUrlOpener(url)
}

func (u HttpUrlOpener) Open() (io.ReadCloser, error) {
	resp, err := http.Get(string(u))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		_ = resp.Body.Close()
		return nil, os.ErrNotExist
	}
	return resp.Body, nil
}

// ByteOpener is an Opener that opens a byte slice as a reader.
type ByteOpener []byte

// NewByteOpener creates a new ByteOpener for the given byte slice.
func NewByteOpener(data []byte) ByteOpener {
	return ByteOpener(data)
}

func (b ByteOpener) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b)), nil
}

// StringOpener is an Opener that opens a string as a reader.
type StringOpener string

// NewStringOpener creates a new StringOpener for the given string.
func NewStringOpener(s string) StringOpener {
	return StringOpener(s)
}

func (s StringOpener) Open() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(s))), nil
}
