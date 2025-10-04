package longspurio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func makeRelPath(root, parent, child string) (string, error) {
	loc := filepath.Clean(filepath.Join(root, parent, child))
	if !strings.HasSuffix(root, string(filepath.Separator)) {
		root = root + string(filepath.Separator)
	}
	if !strings.HasPrefix(loc, root) {
		return "", &os.PathError{
			Op:   "relpath",
			Path: child,
			Err:  fmt.Errorf("path %q is outside root %q", loc, root),
		}
	}
	return strings.TrimPrefix(loc, root), nil
}
