package osv

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "embed"

	"github.com/google/go-cmp/cmp"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/package-url/packageurl-go"
)

//go:embed testdata/pypi.jinja2-2.4.1.json
var jinja2_4_1 string

func Test_Jinja2_4_2(t *testing.T) {
	captured := make([]string, 0)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("unexpected error reading request body: %v", err)
		}
		captured = append(captured, fmt.Sprintf("%s %v", r.Method, string(data)))
		fmt.Fprintln(w, jinja2_4_1)
	}))
	defer ts.Close()

	res, err := queryOsv(ts.URL, &sbommodel.SbomPackageInfo{
		Purl: *packageurl.NewPackageURL(
			packageurl.TypePyPi,
			"",       // namespace
			"Jinja2", // name
			"2.4.1",  // version,
			nil,      // qualifiers
			"",       // subpath
		),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if cmp.Diff(captured, []string{
		`POST {"package":{"name":"Jinja2","ecosystem":"PyPI"},"version":"2.4.1"}}`,
	}) != "" {
		t.Fatalf("unexpected captured requests: %v", captured)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulnerabilities))
	}
	if res.Vulnerabilities[0].ID != "PYSEC-2020-157" {
		t.Fatalf("expected vulnerability ID PYSEC-2020-157, got %s", res.Vulnerabilities[0].ID)
	}
}
