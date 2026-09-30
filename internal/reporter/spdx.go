package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type SPDXReporter struct{}

func (r *SPDXReporter) Name() string {
	return "spdx"
}

func (r *SPDXReporter) Extension() string {
	return "json"
}

type SPDXOutput struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	DocumentName      string             `json:"documentName"`
	DocumentNamespace string             `json:"documentNamespace"`
	Created           string             `json:"created"`
	Creator           string             `json:"creator"`
	Packages          []SPDXPackage      `json:"packages,omitempty"`
	Relationships     []SPDXRelationship `json:"relationships,omitempty"`
}

type SPDXPackage struct {
	SPDXID                    string            `json:"SPDXID"`
	Name                      string            `json:"name"`
	VersionInfo               string            `json:"versionInfo,omitempty"`
	PackageFileName           string            `json:"packageFileName,omitempty"`
	DownloadLocation          string            `json:"downloadLocation"`
	filesAnalyzed             bool              `json:"filesAnalyzed"`
	PackageChecksums          []SPDXChecksum    `json:"packageChecksums,omitempty"`
	PackageExternalReferences []SPDXExternalRef `json:"packageExternalReferences,omitempty"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type SPDXRelationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

func (r *SPDXReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := SPDXOutput{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      "Iris Scan Results",
		DocumentNamespace: "https://iris.pixelcity.dev/scan/" + time.Now().Format("20060102"),
		Created:           time.Now().UTC().Format(time.RFC3339),
		Creator:           "Tool: iris-1.1.0",
	}

	return json.MarshalIndent(output, "", "  ")
}

func init() {
	_ = fmt.Sprintf
}
