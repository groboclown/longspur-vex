package ubuntu

import "github.com/openvex/go-vex/pkg/vex"

// Based on the format figured out from
// https://raw.githubusercontent.com/canonical/ubuntu-security-notices/refs/heads/main/vex/cve/2024/CVE-2024-22861.json
// It's kind of OpenVEX, but not quite.
type UbuntuVEX struct {
	Metadata   UbuntuMetadata   `json:"metadata"`
	Statements []*vex.Statement `json:"statements"`
}

type UbuntuMetadata struct {
	Context   string  `json:"@context"`
	Id        string  `json:"@id"`
	Author    string  `json:"author"`
	Timestamp *string `json:"timestamp"`
	Version   string  `json:"version"`
}
