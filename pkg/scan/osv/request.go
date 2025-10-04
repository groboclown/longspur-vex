package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/anchore/packageurl-go"
	sbommodel "github.com/groboclown/cve-longspur/pkg/sbom/sbom_model"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const OSV_URL = "https://api.osv.dev/v1/query"

func queryOsv(queryUrl string, pkg *sbommodel.SbomPackageInfo) (*cachedResponse, error) {
	eco := mapEcosystem(*pkg)
	if eco == "" {
		// No known ecosystem mapping.
		return &cachedResponse{
			Package:         pkg,
			Vulnerabilities: nil,
		}, fmt.Errorf("no known ecosystem mapping for package type: %s", pkg.Purl.Type)
	}
	req := VulnRequest{
		Package: VulnPackage{
			Name:      pkg.Purl.Name,
			Ecosystem: eco,
		},
		// Note: null version is fine.
		Version: pkg.Purl.Version,
	}
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(queryUrl, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var vulnResp VulnResponse
	if err := json.NewDecoder(resp.Body).Decode(&vulnResp); err != nil {
		return nil, err
	}
	return &cachedResponse{
		Package:         pkg,
		Vulnerabilities: vulnResp.Vulnerabilities,
	}, nil
}

func mapEcosystem(info sbommodel.SbomPackageInfo) string {
	if eco, ok := ecosystemMap[strings.ToLower(info.Purl.Type)]; ok {
		return string(eco)
	}
	return ""
}

type VulnResponse struct {
	Vulnerabilities []*osvschema.Vulnerability `json:"vulns"`
}

type cachedResponse struct {
	Package         *sbommodel.SbomPackageInfo
	Vulnerabilities []*osvschema.Vulnerability
}

type VulnRequest struct {
	Package VulnPackage `json:"package"`
	Version string      `json:"version,omitempty"`
}

type VulnPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// List of all the ecosystems at the time of this writing.
var ecosystems = []osvschema.Ecosystem{
	osvschema.EcosystemAlmaLinux,
	osvschema.EcosystemAlpaquita,
	osvschema.EcosystemAlpine,
	osvschema.EcosystemAndroid,
	osvschema.EcosystemBellSoftHardenedContainers,
	osvschema.EcosystemBioconductor,
	osvschema.EcosystemBitnami,
	osvschema.EcosystemChainguard,
	osvschema.EcosystemConanCenter,
	osvschema.EcosystemCRAN,
	osvschema.EcosystemCratesIO,
	osvschema.EcosystemDebian,
	osvschema.EcosystemEcho,
	osvschema.EcosystemGHC,
	osvschema.EcosystemGitHubActions,
	osvschema.EcosystemGo,
	osvschema.EcosystemHackage,
	osvschema.EcosystemHex,
	osvschema.EcosystemKubernetes,
	osvschema.EcosystemLinux,
	osvschema.EcosystemMageia,
	osvschema.EcosystemMaven,
	osvschema.EcosystemMinimOS,
	osvschema.EcosystemNPM,
	osvschema.EcosystemNuGet,
	osvschema.EcosystemOpenEuler,
	osvschema.EcosystemOpenSUSE,
	osvschema.EcosystemOSSFuzz,
	osvschema.EcosystemPackagist,
	osvschema.EcosystemPhotonOS,
	osvschema.EcosystemPub,
	osvschema.EcosystemPyPI,
	osvschema.EcosystemRedHat,
	osvschema.EcosystemRockyLinux,
	osvschema.EcosystemRubyGems,
	osvschema.EcosystemSUSE,
	osvschema.EcosystemSwiftURL,
	osvschema.EcosystemUbuntu,
	osvschema.EcosystemWolfi,
}

// Mapping of the ecosystems to the packageurl types, at the time of this writing.
var knownEcosystemMap = map[string]osvschema.Ecosystem{
	// packageurl Known Types
	// packageurl.TypeAlpm: ?
	packageurl.TypeApk: osvschema.EcosystemAlpine,
	// packageurl.TypeBitbucket: ?
	packageurl.TypeBitnami: osvschema.EcosystemBitnami,
	packageurl.TypeCargo:   osvschema.EcosystemCratesIO,
	// packageurl.TypeCocoapods: ?
	// packageurl.TypeComposer: ?
	packageurl.TypeConan: osvschema.EcosystemConanCenter,
	// packageurl.TypeConda: ?,
	packageurl.TypeCran:   osvschema.EcosystemCRAN,
	packageurl.TypeDebian: osvschema.EcosystemDebian,
	// packageurl.TypeDocker: ?
	packageurl.TypeGem: osvschema.EcosystemRubyGems,
	// packageurl.TypeGeneric: ?
	packageurl.TypeGithub:  osvschema.EcosystemGitHubActions, // ?
	packageurl.TypeGolang:  osvschema.EcosystemGo,
	packageurl.TypeHackage: osvschema.EcosystemHackage,
	packageurl.TypeHex:     osvschema.EcosystemHex,
	// packageurl.TypeHuggingface: ?
	// packageurl.TypeMLFlow: ?
	packageurl.TypeMaven: osvschema.EcosystemMaven,
	packageurl.TypeNPM:   osvschema.EcosystemNPM,
	packageurl.TypeNuget: osvschema.EcosystemNuGet,
	// packageurl.TypeOCI: ?
	packageurl.TypePub:  osvschema.EcosystemPub,
	packageurl.TypePyPi: osvschema.EcosystemPyPI,
	// packageurl.TypeQpkg: ?
	packageurl.TypeRPM:   osvschema.EcosystemRedHat,
	packageurl.TypeSWID:  osvschema.EcosystemLinux, // ?
	packageurl.TypeSwift: osvschema.EcosystemSwiftURL,

	// packageurl Candidate types
	// packageurl.TypeApache: ?
	packageurl.TypeAndroid: osvschema.EcosystemAndroid,
	// packageurl.TypeAtom: ?
	// packageurl.TypeBower: ?
	// packageurl.TypeBrew: ?
	// packageurl.TypeBuildroot: ?
	// packageurl.TypeCarthage: ?
	// packageurl.TypeChef: ?
	// packageurl.TypeChocolatey: ?
	// packageurl.TypeClojars: ?
	// packageurl.TypeCoreos: ?
	// packageurl.TypeCpan: ?
	// packageurl.TypeCtan: ?
	// packageurl.TypeCrystal: ?
	// packageurl.TypeDrupal: ?
	// packageurl.TypeDtype: ?
	// packageurl.TypeDub: ?
	// packageurl.TypeElm: ?
	// packageurl.TypeEclipse: ?
	// packageurl.TypeGitea: ?
	// packageurl.TypeGitlab: ?
	// packageurl.TypeGradle: ?
	// packageurl.TypeGuix: ?
	// packageurl.TypeHaxe: ?
	// packageurl.TypeHelm: ?
	// packageurl.TypeJulia: ?
	// packageurl.TypeLua: ?
	// packageurl.TypeMelpa: ?
	// packageurl.TypeMeteor: ?
	// packageurl.TypeNim: ?
	// packageurl.TypeNix: ?
	// packageurl.TypeOpam: ?
	// packageurl.TypeOpenwrt: ?
	// packageurl.TypeOsgi: ?
	// packageurl.TypeP2: ?
	// packageurl.TypePear: ?
	// packageurl.TypePecl: ?
	// packageurl.TypePERL6: ?
	// packageurl.TypePlatformio: ?
	// packageurl.TypeEbuild: ?
	// packageurl.TypePuppet: ?
	// packageurl.TypeSourceforge: ?
	// packageurl.TypeSublime: ?
	// packageurl.TypeTerraform: ?
	// packageurl.TypeVagrant: ?
	// packageurl.TypeVim: ?
	// packageurl.TypeWORDPRESS: ?
	// packageurl.TypeYocto: ?

	// Custom
	"apt": osvschema.EcosystemUbuntu,
}

var ecosystemMap = map[string]osvschema.Ecosystem{}

func init() {
	// Straight mappings first.
	for _, eco := range ecosystems {
		ecosystemMap[strings.ToLower(string(eco))] = eco
	}
	// Overrides and additions next.
	for k, v := range knownEcosystemMap {
		ecosystemMap[k] = v
	}
}
