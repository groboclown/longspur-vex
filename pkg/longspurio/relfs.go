package longspurio

import (
	"io"

	"github.com/groboclown/cve-longspur/internal/fileutil"
)

// A relative "filesystem", where paths are relative to some root.
// It can be based on a URL or a directory on disk or something else entirely.
type RelFs interface {
	// Open opens the named file for reading.
	Open(name string) (io.ReadCloser, error)

	// OpenReader returns an Opener for the named file.
	OpenReader(name string) (OpenReader, error)

	// RelPath returns a new resource relative to this filesystem.
	Get(name string) (*RelResource, error)

	// RelativePath returns the relative path from parent to child.
	// If the paths are not related, an error is returned.
	// If the child starts with '/', it is assumed to be relative to the root of the filesystem.
	// This follows '..' and '.' elements.
	// If the child extends beyond the root of the filesystem, an error is returned.
	// This assumes nothing about the parent; if it's a resource as opposed to a directory,
	// then ".." will need to be used to get to the parent directory first.
	RelativePath(parent string, child string) (string, error)
}

// A resource in a relative filesystem.
type RelResource struct {
	path string
	fs   RelFs
}

func NewRelResource(path string, fs RelFs) *RelResource {
	return &RelResource{
		path: path,
		fs:   fs,
	}
}

func (r *RelResource) Path() string {
	return r.path
}

func (r *RelResource) Fs() RelFs {
	return r.fs
}

func (r *RelResource) Open() (io.ReadCloser, error) {
	return r.fs.Open(r.path)
}

func (r *RelResource) ReadAll() ([]byte, error) {
	rc, err := r.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Reader returns a ReadCloser for the resource.
// If the resource cannot be opened, the returned ReadCloser will return an error on Read().
func (r *RelResource) Reader() io.ReadCloser {
	rc, err := r.Open()
	if err != nil {
		return fileutil.NewErrorReader(err)
	}
	return rc
}

func (r *RelResource) OpenReader() (OpenReader, error) {
	return r.fs.OpenReader(r.path)
}

func (r *RelResource) GetRelative(name string) (*RelResource, error) {
	loc, err := r.fs.RelativePath(r.path, name)
	if err != nil {
		return nil, err
	}
	return r.fs.Get(loc)
}
