package longspurio

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
)

// OneEntryRelFs is a simple filesystem with a single file entry.
type OneEntryRelFs struct {
	path string
	data []byte
}

var _ RelFs = &OneEntryRelFs{}

// NewOneEntryRelFs creates a new OneEntryRelFs with the given path and data.
func NewOneEntryRelFs(path string, data []byte) *OneEntryRelFs {
	path = filepath.Clean(path)
	return &OneEntryRelFs{
		path: path,
		data: data,
	}
}

func (o *OneEntryRelFs) Open(name string) (io.ReadCloser, error) {
	if name != o.path {
		return nil, &os.PathError{
			Op:   "open",
			Path: name,
			Err:  os.ErrNotExist,
		}
	}
	return io.NopCloser(bytes.NewReader(o.data)), nil
}

func (o *OneEntryRelFs) OpenReader(name string) (OpenReader, error) {
	if name != o.path {
		return nil, &os.PathError{
			Op:   "open",
			Path: name,
			Err:  os.ErrNotExist,
		}
	}
	return NewByteOpener(o.data), nil
}

func (o *OneEntryRelFs) Get(name string) (*RelResource, error) {
	loc := filepath.Clean(name)
	if loc != o.path {
		return nil, &os.PathError{
			Op:   "get",
			Path: name,
			Err:  os.ErrNotExist,
		}
	}
	return &RelResource{
		path: o.path,
		fs:   o,
	}, nil
}

func (o *OneEntryRelFs) RelativePath(parent string, child string) (string, error) {
	if parent != o.path {
		return "", &os.PathError{
			Op:   "relpath",
			Path: parent,
			Err:  os.ErrNotExist,
		}
	}
	loc := filepath.Clean(filepath.Join(parent, child))
	if loc != o.path {
		return "", &os.PathError{
			Op:   "get",
			Path: child,
			Err:  os.ErrNotExist,
		}
	}
	return o.path, nil
}

type ByteTreeRelFs struct {
	data map[string][]byte
}

var _ RelFs = &ByteTreeRelFs{}

func NewByteTreeRelFs(data map[string][]byte) *ByteTreeRelFs {
	tree := make(map[string][]byte)
	for k, v := range data {
		k = filepath.Clean(k)
		tree[k] = v
	}
	return &ByteTreeRelFs{
		data: data,
	}
}

func (b *ByteTreeRelFs) Open(name string) (io.ReadCloser, error) {
	path, err := b.RelativePath(".", name)
	if err != nil {
		return nil, err
	}
	data, ok := b.data[path]
	if !ok {
		panic("file not found after RelativePath succeeded")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *ByteTreeRelFs) OpenReader(name string) (OpenReader, error) {
	path, err := b.RelativePath(".", name)
	if err != nil {
		return nil, err
	}
	data, ok := b.data[path]
	if !ok {
		panic("file not found after RelativePath succeeded")
	}
	return NewByteOpener(data), nil
}

func (b *ByteTreeRelFs) Get(name string) (*RelResource, error) {
	path, err := b.RelativePath(".", name)
	if err != nil {
		return nil, err
	}
	return NewRelResource(path, b), nil
}

func (b *ByteTreeRelFs) RelativePath(parent string, child string) (string, error) {
	loc := filepath.Clean(filepath.Join(parent, child))
	_, ok := b.data[loc]
	if !ok {
		return "", &os.PathError{
			Op:   "get",
			Path: loc,
			Err:  os.ErrNotExist,
		}
	}
	return loc, nil
}
