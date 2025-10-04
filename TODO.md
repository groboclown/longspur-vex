# Task List for Longspur

## Project Definition

*Status: mostly done*

The project must define its goals and scope limits.

This also includes the project basics.

- [x] Decide on a name
    - Complete: Longspur, after the bird.
- [x] Decide on a license
    - Complete: Apache 2.0
- [x] Define the project goals.  Includes the differentiator from other projects.
    - Complete: defined in the [readme](README.md)
- [x] Land on a language
    - Complete: Go, as most of the libraries we want to use are themselves written in Go.
- [ ] Define the contributing guidelines.
- [ ] Set up the GitHub project.
- [ ] Define the code of conduct.


## Basic File Assembly and Collation

*Status: started*

Once coding begins, the tooling should first include the parsers and logic for processing the SBOM and VEX file formats.  With this foundation, we can then look at how to group these together to make strong judgments for dealing with CVE reports, which then allows for defining various approaches, and what gaps the user can fill.

The importing of data, at this point, just needs the data; it does not need the logic for finding or correct pulling.


- [x] Create the CLI program entrypoint.
    - Complete
- [ ] Create the initial library API.
    - We want a stable API library for others to rely on, so that the ecosystem can benefit from it.
    - We may fork the API into a separate project from the CLI.
    - [x] [SBOM model](pkg/sbom/sbom_model/model.go)
    - [x] [VEX model](pkg/vex/vex_model/model.go)
    - [x] [Scan results model](pkg/scan/scan_model/results.go)
- [ ] Import SBOM sources.
    - [x] [SPDX](pkg/sbom/spdx/decode.go)
    - [x] [CycloneDX](pkg/sbom/cdx/decode.go)
    - [ ] [Syft](pkg/sbom/syft/decode.go); still needs implementation
- [x] Import VEX sources.
    - [x] [OpenVEX v0.2.0](pkg/vex/openvex/decode.go)
    - [x] [OpenVEX v0.0.1](pkg/vex/openvex/decode_v001.go)
    - [x] [CycloneDX](pkg/vex/cdx/decode.go)
    - [x] [CSAF](pkg/vex/csaf/decode.go)
    - [x] [Ubuntu variant on OpenVEX](pkg/vex/ubuntu/decode.go)
- [ ] Import vulnerability reports.
    - [x] [OSV](pkg/scan/osv/scanner.go)
    - [ ] CVE
- [ ] Unify multiple SBOMs into a single object.
    - Requires conflict resolution, which can come from control patterns or explicit action.  This is being handled through declaration of SBOM sources as either `declarative` or `discovery`.  `discovery` SBOM files perform best-guess analysis of a collection of files, while `declarative` uses something similar to a "package lock" file to extract exact dependency trees.  The `discovery` can help identify items available missed by the package lock, but must take a back seat to the declarative SBOM.


## Build and Release

*Status: barely anything*

- [x] Create the Makefile.
    - [Complete](Makefile), though it will of course need refinement.
- [ ] Add GitHub actions for PR validation.
- [ ] Add branch rules.
- [ ] Add GitHub actions for release automation.
- [ ] Create project signing keys, with the public key stashed in a "good" location.
