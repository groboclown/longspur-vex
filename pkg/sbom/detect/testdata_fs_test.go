package detect_test

import (
	_ "embed"

	"github.com/groboclown/cve-longspur/pkg/longspurio"
)

//go:embed testdata/c-spdx2.2.spdx
var c_spdx22_spdx []byte

//go:embed testdata/c-spdx3.0.spdx.json
var c_spdx30_json []byte

//go:embed testdata/go-spdx2.2.spdx.json
var go_spdx22_json []byte

//go:embed testdata/ubuntu.cdx.json
var u_cdx_json []byte

//go:embed testdata/ubuntu.cdx.xml
var u_cdx_xml []byte

//go:embed testdata/ubuntu-spdx2.2.spdx.json
var u_spdx22_json []byte

//go:embed testdata/ubuntu-spdx2.2.spdx
var u_spdx22_spdx []byte

//go:embed testdata/ubuntu-spdx2.3.spdx.json
var u_spdx23_json []byte

//go:embed testdata/ubuntu-spdx2.3.spdx
var u_spdx23_spdx []byte

//go:embed testdata/ubuntu-syft.json
var u_syft_json []byte

var TestDataFs = longspurio.NewByteTreeRelFs(map[string][]byte{
	"c-spdx2.2.spdx":           c_spdx22_spdx,
	"c-spdx2.2.spdx.txt":       c_spdx22_spdx,
	"c-spdx3.0.spdx.json":      c_spdx30_json,
	"c-spdx3.0.spdx.json.txt":  c_spdx30_json,
	"go-spdx2.2.spdx.json":     go_spdx22_json,
	"go-spdx2.2.spdx.json.txt": go_spdx22_json,
	"ubuntu.cdx.json":          u_cdx_json,
	"ubuntu.cdx.xml":           u_cdx_xml,
	"ubuntu.spdx2.2.spdx.json": u_spdx22_json,
	"ubuntu.spdx2.2.spdx":      u_spdx22_spdx,
	"ubuntu.spdx2.3.spdx.json": u_spdx23_json,
	"ubuntu.spdx2.3.spdx":      u_spdx23_spdx,
	"ubuntu.syft.json":         u_syft_json,
})

func GetTestResource(name string) *longspurio.RelResource {
	r, e := TestDataFs.Get(name)
	if e != nil {
		panic(e)
	}
	return r
}
