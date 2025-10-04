/*
SPDX-License-Identifier: Apache-2.0
*/
package fileutil

import "strings"

// EnsureExtension ensures that the provided path ends with the given extension,
// The extension should include the leading dot, e.g. ".txt", and be lower-case.
func EnsureExtension(path string, extension string) string {
	if strings.HasSuffix(strings.ToLower(path), extension) {
		return path
	}
	if strings.HasSuffix(path, ".") {
		return path + extension
	}
	return path + "." + extension
}
