// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cvelongspur

import (
	_ "embed"
	"strings"
)

//go:embed version.txt
var version string

// Version returns the current version of the application / library.
func Version() string {
	for _, line := range strings.Split(version, "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
			return strings.TrimSpace(line)
		}
	}
	panic("version not found")
}
