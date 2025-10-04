package fileutil

import "io"

type ErrorReader struct {
	err error
}

var _ io.ReadCloser = (*ErrorReader)(nil)

func NewErrorReader(err error) *ErrorReader {
	return &ErrorReader{err: err}
}

func (e *ErrorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func (e *ErrorReader) Close() error {
	return nil
}
