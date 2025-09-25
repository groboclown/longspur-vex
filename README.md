# Longspur - SBOM, VEX, and CVE Assessment Tool

A tool for managing SBOMS and VEX documents for a project, and verify them against CVEs.

* **SBOM** - Software Bill of Materials.  Stores a product's list of dependencies.
* **VEX** - Vulnerability Exploitability Exchange document.  Stores analysis results of how CVEs affect a product that in some way was affected by the CVE (either was the source of the CVE or has a dependency on something that has the CVE against it).
* **CVE** - Common Vulnerability and Exposures.  Here, used as a generic term for an indentifier for a publicly disclosed vulnerability, whether a [CVE](https://nvd.nist.gov/general/cve-process) proper, a [GHSA](https://github.com/advisories), or any number of other sources.

Well Managed projects will construct an SBOM for the product itself, and ensure that any vulnerabilities in its dependencies do not affect the product.  They will also inspect the test dependencies and build environment dependencies, to help protect against supply chain attacks.

Unfortunately, we're still in the early days of sorting all these layers of trust out.  While the ecosystem has settled down on CVEs and SBOMs, VEX documents still have a long way to go.  We don't have standard repositories for VEX, nor do we have a standard way to manage them from within a project.


# Goals

This tool aims to:

* Construct a method to store VEX-like statements in your project repository, to keep a record of past analysis.
* Construct the start of VEX document discovery from the Internet.  We plan on making this a long term effort, and will be under flux as teams figure out the right way to store these and make them accessible.
* Ingest SBOM documents that describe the product, and incorporate them into the analysis.
* Pull CVE records for items described in the SBOM documents.
* Compare the CVE records against the SBOMs and dependencies' VEX statements.
* As a consequence of the above items, construct a single SBOM and VEX document for your project.  At the moment, we consider pushing these documents to another location out of scope.


# Friction

While there exist many tools that do parts of this, none seem to do it as a unified whole.  Additionally, existing tools have their own share of issues that come into conflict with the goals of this tool:

* If a project generates multiple SBOM files, they may refer to the same dependency in different ways.
  * For example, a NodeJS project can construct an SBOM based on the dependencies, and another SBOM from the container image that deploys into production.  However, the build for the container image often strips out necessary information, such as versioning, for packages declared in the project SBOM.  The tool will need a way to reconcile these differences.
* A VEX document issued by one dependency will only include an analysis for how a CVE affects it.
  * For example, a web server framework WSF uses an HTTP communication module HCM.  If WSF declares in its VEX that a CVE against HCM does not affect WSF because it doesn't use the affected functionality, your project can only use this analysis for the HCM CVE through the WSF dependency.  If your project uses HCM directly, then your project must still perform its own analysis of the HCM CVE based on how you uses it.
* The project should issue its own VEX document.  This should include references to the VEX documents that were used in the CVE analysis, as well as examining that it covers all known CVEs.


# Status

Currently in the planning and experimental / Proof of Concept phase.  See [TODO.md](TODO.md) for the full list of tasks constructed so far.


# License

[Apache 2.0](LICENSE)
