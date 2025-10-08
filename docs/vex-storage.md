# Methods for the Storage of VEX Documents

As teams slowly adopt the use of VEX documents, they need to plan a method for maintaining these documents.  Currently, no one has established a single standard around this.  To add to the difficulty, different repositories have different usage patterns, which requires a standard to take these into account.

## Patterns

### Product or Library with Versioned Releases

A common OSS pattern has a product with versioned releases, meaning that the owning team maintains several version product lines in parallel (e.g. v1.x and v2.x, each with their own patch releases).

Because the teams maintain the products in different branches, this leads to difficulty in maintaining how the discovered dependency CVEs affect each product line.  In particular, because it means understanding which branch to store the VEX documents.

Some ideas for where to maintain the VEX documents:

* In the `main` branch:
    * The `main` branch commonly maintains the latest stable version code.
    * Maintenance Positives and Negatives:
        * Merging into this branch with changes to the VEX documents means introducing commits (which usually the changelog must include references to) outside normal release schedules.  This can lead to a cluttered commit history, with different forces behind them.
    * Outsiders' discovery mechanism:
        * It contains documents for all the versions' affected, which means it offers a single location for other projects to discover the VEX documents.
        * Requires establishing a sub-directory standard naming.
        * The project can have a single VEX document containing the analysis on all the affected versions.
        * Easy mapping of the project to the branch and file location.
        * As the project owns the location of the analyses, outsiders must trust that the repository doesn't drop information for old versions.
    * File organization:
        * One location that contains a CVE and version division.
* In each version's branch:
    * The project maintains each version in its own branch.
    * Maintenance Positives and Negatives:
        * Each version maintains its own VEX document.  This makes the commit history for each branch related to just that branch's contents.
        * Merges into the branch happen outside releases.
        * Forces duplication of analysis into each branch, if a set of versions have the same analysis.
    * Outsiders' discovery mechanism:
        * Projects use branches on old versions differently, which makes mapping the affected version to the branch boutique, or forces every project to handle branches in a set pattern.
        * Requires establishing a sub-directory standard naming.
    * File organization:
        * Split of documents between branches, summarizing the CVEs for the single version.
    * Initial assessment:
        * The worst of the solutions and shouldn't be considered.
* Dedicated branch just for VEX documents.
    * Single location dedicated to storing VEX documents, within the hosting project.
    * Maintenance Positives and Negatives:
        * Generally requires a branch that has no history in common with the other branches.  While not itself a problem, can pose some issues to teams unfamiliar with the source control tools.
        * Allows for a standard commit flow to maintain the document, though, because of the separate history, can make it easy for committers to make mistakes.
    * Outsiders' discovery mechanism:
        * Non-obvious to visitors on where to find the documents.
        * Requires establishing a branch naming standard.
* Separate repository:
    * A separate repository dedicated to just VEX documents.
    * Maintenance Positives and Negatives:
        * Allows for standard commit flows to maintain the documents.
        * Lives outside the primary project, so that creates a disconnect from the source.
    * Outsiders' discovery mechanism:
        * Projects that want to discover the VEX documents must know how to map the source repository to the VEX storage repository.
* Unified registry:
    * A third party maintains the VEX documents.
    * Maintenance Positives and Negatives:
        * Similar to library releases to registries, it requires proper trust validation for uploading the VEX documents.
        * Teams have established methods for releasing versions, and this adds another pipeline.  If performed through automation such as GitHub Actions, then this adds an extra layer of file production and publication, meaning that the team must establish its own method for maintaining the documents that corresponds to one of the above methods.
        * Allows teams to have flexibility in maintaining the documents, though it doesn't enforce rigor.
        * The unified registry must have a method for maintaining a history of the documents, and ensure that old analyses aren't dropped.
    * Outsiders' discovery mechanism:
        * Single place with an established discovery mechanism for multiple projects.


### Product Always at "Head" Version

For Software as a Service (or Platform as a Service, or what have you), the software is always at "head", or "head + N" if it supports developer channels.  In this case, the project does not need to support maintaining 

This style of project can reuse many of the above mechanisms.

Issues around maintaining historical records lessens as, with the continuing march of "head", old versions don't matter.  Discovered issues with old versions (such as susceptibility to zero days during a time frame) require alternative methods of announcements.


## Search Mechanisms

The usual ordering for looking for VEX documents comes from this flow:

1. Project A generates one or more SBOM files for itself.
2. Project A scans the SBOM files for CVEs.
3. If the scan detects a CVE against project B, then Project A looks for VEX documents about that issue for each dependency parent of project B.

This means that the forcing function for discovering VEX documents comes from the CVEs.

An alternative approach for looking for VEX documents comes from finding *updates* to analyses.  The VEX documents allow for changing or updating analyses, which means the downstream projects will aim to periodically scan for these changes.

The above describes a *pull* mechanism.  A *push* mechanism requires much more infrastructure on the part of both downstream and upstream projects, and seems to lie outside the realm of practicality for OSS projects.  It might work for VEX registries.

A project may store the documents in different ways depending on its scope.  For example, a simple library with four dependencies may opt for a single VEX document.  For something like Ubuntu, which maintains thousands of dependencies, storing the documents by CVE first makes more sense.


## Proposal 1

A project or registry maintains a "document store" of VEX documents.  Outsiders MUST access it through a root URL.  The URL SHOULD use secure transit protocols.  Outsiders may read the contents of the location at `${URL}/.vex-catalog.json`, a JSON formatted file, which contains:

*TODO make this reflect the examples below.*

* The catalog schema version.
* The VEX document URL root.  This may differ from the catalog file root; for example, a project may contain the catalog file in the main branch of the source repository, but hosts the VEX documents elsewhere.
* One of:
    * A list of projects, whose VEX analyses the the document store contains.  Each project contains:
        * The project Package URL (PURL), optionally containing the version.
        * The document layout pattern.  This takes the form of a relative URL pattern to the VEX document root, with pattern elements in the form `{PATTERN}` inside the relative URL.
        * Optional: the last update time of the document store.
    * A single URL pattern that maps the vulnerability ID to a single, corresponding VEX document.  This will apply to all products with an analysis of that vulnerability ID.
    * A list of URLs that map the vulnerability ID to the secondary VEX document catalog.  This creates a double index, where the root index indicates how to look up the second index based on the CVE.  Each existing index at that position MUST be a catalog which contains just the list of projects.
* A list of supported vulnerability ID formats (optional).  This applies only for catalog files which contain the vulnerability ID within the pattern.  Unfortunately, due to the different vulnerability registries, this creates a series of aliases.  While it's possible for a VEX file index to support many aliases, that adds a high burden on the file storage.  Instead, this list contains the starting character pattern allowed by the index.  For example, it can contain `CVE-` to indicate it supports the NIST CVE index.

The supported `{PATTERN}` values include:

* `{VULN}` - the full vulnerability ID.  This MUST match one of the supported vulnerability ID formats within the document.
* `{VULN:x}` - The first *x* characters of the vulnerability ID.  For ID `ABCD`, `{VULN:1}` means `A`, `{VULN:3}` means `ABC`, `{VULN:6}` means `ABCD`.
* `{VULN:-x}` - The last *x* characters of the vulnerability ID.  For ID `ABCD`, `{VULN:-1}` means `D`, `{VULN:-3}` means `BCD`, `{VULN:-6}` means `ABCD`.
* `{VULN:x:y}` - Characters *x* to *y* (inclusive) of the vulnerability ID.  For ID `ABCD`, `{VULN:2:3}` means `BC`.
* `{VERSION}` - the version number of the project to look up.  This uses the project's versioning semantics as-is.
* `{VERSION@x}` - the first *x* "segments" of the version, where each segment is separated by one character from within the set `.-_,:/@`.  If the project version number is `v13.6-beta`, then `{VERSION@1}` is `v13`, `{VERSION@2}` is `v13.6`, `{VERSION@3}` is `v13.6-beta`, and `{VERSION@4}` is `v13.6-beta`.

The resulting pattern MUST first be percent encoded before inserted into the final URL position.

Because the URL pattern is per-project, the project name exists within the URL, without the need to introduce the `{PATTERN}`.

### Example: Simple Library

We have a simple library, which has just one major version, and is hosted in GitHub.  We decide to keep the vulnerability analyses within a single VEX document, in its own branch, to keep from cluttering the commit history, while also maintaining the version history of the document.

The project stores the catalog at the root of the main branch.  Because many projects use GitHub to maintain their source, and because the library publishes a SITE reference at `https://github.com/octocat/cool-project`, consumers of the library detect the simple GitHub project URL, and attempt to look for the catalog at `https://raw.githubusercontent.com/octocat/cool-project/refs/heads/main/.vex-catalog.json`.  It looks like:

```json
{
    "$schema": "https://TBD/v1.json",
    "$comment": "This stores our project's vulnerability analyses in the 'vex-documents' branch, in a single file.",
    "kind": "url",
    "url": "https://raw.githubusercontent.com/octocat/cool-project/refs/heads/vex-documents/vex.cdx.json",
    "format": "CyconeDX"
}
```

### Example: Large Project

We have a large project, which contains many libraries in a mono repo, and has many dependencies, and each of them can have their own group of maintainers.  Because of this the team must maintain the vulnerability analyses on their own terms.  Some libraries changed names, which requires aliasing.

The project hosts a primary reference that keeps each project's VEX documents in their own branch:

```json
{
    "$schema": "https://TBD/v1.json",
    "$comment": "Each project can maintain its analyses in its own branch, so the branch name is left off the root.",
    "kind": "projects",
    "root": "https://raw.githubusercontent.com/octocat/large-project/refs/heads/",
    "projects": [
        {
            "purl": ["pkg:maven/octocat.large.project/small-lib"],
            "rel": "small-lib/.vex/{VERSION@1}.json",
            "format": "OpenVEX@0.2.0"
        },
        {
            "purl": [
                "pkg:maven/octocat.large.project/ancient-lib",
                "pkg:maven/octocat.large.project/lib1"
            ],
            "vulnerabilities": {
                "GHSA": {
                    "rel": "lib1/.vex/GHSA/_{VULN:-4}/{VULN}.json",
                    "format": "OpenVEX@0.2.0"
                }
            }
        }
    ]
}
```

### Example: Ubuntu

At the time of this writing, Canonical maintains the Ubuntu security notices in a dedicated GitHub repository at [https://github.com/canonical/ubuntu-security-notices](https://github.com/canonical/ubuntu-security-notices).  It stores the documents in a kind-of OpenVEX format (with document metadata that differs than the standard), and collects all analyses together on a per vulnerability basis.

If this repository were to conform to this proposal, then Canonical would publish the catalog file in a well established central location, and it would look like:

```json
{
    "$schema": "https://TBD/v1.json",
    "kind": "vulnerabilities",
    "root": "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/refs/heads/main/vex/cve/",
    "vulnerabilities": {
        "CVE": {
            "rel": "{VULN:5:8}/{VULN}.json",
            "format": "OpenVEX@0.2.0-metadata"
        }
    }
}
```

### Example: VexHub

The [VexHub](https://github.com/aquasecurity/vexhub) is one of several attempts to collect VEX documents into one place.  It allows projects to register their site so that the hub crawls the site to get the latest version of the VEX document.  It stores the files based on the source package, so that the files remain unaltered from their original form.

In this case, each package must be called out.

```json
{
    "$schema": "https://TBD/v1.json",
    "kind": "projects",
    "root": "https://raw.githubusercontent.com/aquasecurity/vexhub/refs/heads/main/pkg",
    "projects": [
        {
            "purl": ["pkg:golang/github.com/aquasecurity/trivy"],
            "rel": "golang/github.com/aquasecurity/trivy/trivy.openvex.json",
            "format": "OpenVEX@0.2.0"
        },
        {
            "purl": ["pkg:golang/github.com/k3s-io/helm-set-status"],
            "rel": "golang/github.com/k3s-io/helm-set-status/scan.openvex.json",
            "format": "OpenVEX@0.2.0"
        }
    ]
}
```

Alternatively, this catalog format allows for embedding other catalogs, without harvesting the files.

```json
{
    "$schema": "https://TBD/v1.json",
    "kind": "catalog",
    "catalog": {
        {
            "kind": "product",
            "purl": ["pkg:golang/github.com/aquasecurity/trivy"],
            "url": ["https://raw.githubusercontent.com/aquasecurity/trivy/refs/main/.vex/trivy.openvex.json"],
            "format": "OpenVEX@0.2.0"
        },
        {
            "kind": "reference",
            "$comment": "This points to another site that hosts its own catalog file.",
            "url": ["https://raw.githubusercontent.com/octocat/large-project/refs/heads/main/.vex-catalog.json"],
            "format": "https://TBD/v1.json"
        }
    }
}
```
