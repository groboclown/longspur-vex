package sbommodel

import "github.com/package-url/packageurl-go"

func ExtractPurlsFromPackages(pkgs []*SbomPackage) []packageurl.PackageURL {
	purls := make([]packageurl.PackageURL, 0, len(pkgs))
	for _, p := range pkgs {
		purls = append(purls, p.SbomPackageInfo.Purl)
	}
	return purls
}

func ClonePurl(p packageurl.PackageURL) packageurl.PackageURL {
	q := make(packageurl.Qualifiers, len(p.Qualifiers))
	copy(q, p.Qualifiers)

	return packageurl.PackageURL{
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: q,
		Subpath:    p.Subpath,
	}
}
