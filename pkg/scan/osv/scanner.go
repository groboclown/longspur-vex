package osv

import (
	"context"
	"sync"

	"github.com/groboclown/cve-longspur/internal/cache"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	scanmodel "github.com/groboclown/cve-longspur/pkg/scan/scan_model"
)

type OsvScanner struct {
	queryUrl string // for unit testing
	req      *cache.RequestCache[string, *cachedResponse]
}

var _ scanmodel.Scanner = &OsvScanner{}

func NewOsvScanner() *OsvScanner {
	return &OsvScanner{
		queryUrl: OSV_URL,
		req:      cache.NewRequestCache[string, *cachedResponse](),
	}
}

func (s *OsvScanner) Scan(
	packages []*sbommodel.SbomPackageInfo,
	ctx context.Context,
) (*scanmodel.ScanResults, error) {
	vulns_ch := make(chan *scanmodel.PackageScanResults, len(packages))
	errs_ch := make(chan error, len(packages))
	var wg sync.WaitGroup
	for _, pkg := range packages {
		wg.Add(1)
		go func(pkg *sbommodel.SbomPackageInfo) {
			defer wg.Done()
			s.scanPackage(pkg, vulns_ch, errs_ch)
		}(pkg)
	}

	collected_vulns := make(chan []*scanmodel.PackageScanResults, 1)
	wg.Go(func() {
		var results []*scanmodel.PackageScanResults
		for v := range vulns_ch {
			results = append(results, v)
		}
		collected_vulns <- results
	})

	collected_errs := make(chan []error, 1)
	wg.Go(func() {
		defer wg.Done()
		var results []error
		for e := range errs_ch {
			results = append(results, e)
		}
		collected_errs <- results
	})

	wg.Wait()

	vulns := <-collected_vulns
	errs := <-collected_errs
	if len(collected_errs) > 0 {
		return nil, scanmodel.NewScanError("OSV Scan", errs)
	}
	return &scanmodel.ScanResults{
		Packages: vulns,
	}, nil
}

func (s *OsvScanner) scanPackage(
	pkg *sbommodel.SbomPackageInfo,
	res chan<- *scanmodel.PackageScanResults,
	errs chan<- error,
) {
	r, e := s.req.Get(s.makeCacheKey(pkg), func() (*cachedResponse, error) {
		return queryOsv(s.queryUrl, pkg)
	})
	if r != nil {
		res <- &scanmodel.PackageScanResults{
			Package:         pkg,
			Vulnerabilities: r.Vulnerabilities,
		}
	}
	if e != nil {
		errs <- e
	}
}

func (s *OsvScanner) makeCacheKey(pkg *sbommodel.SbomPackageInfo) string {
	if pkg == nil {
		return ""
	}
	if pkg.Version == nil {
		return pkg.Name
	}
	return pkg.Name + "|" + *pkg.Version
}
