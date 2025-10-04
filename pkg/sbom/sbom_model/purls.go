package sbommodel

import "github.com/package-url/packageurl-go"

func ExtractPurlsFromPackages(pkgs []*SbomPackage) []packageurl.PackageURL {
	purls := make([]packageurl.PackageURL, 0, len(pkgs))
	for _, p := range pkgs {
		purls = append(purls, p.SbomPackageInfo.Purl)
	}
	return purls
}
