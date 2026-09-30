package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type CycloneDXReporter struct{}

func (r *CycloneDXReporter) Name() string {
	return "cyclonedx"
}

func (r *CycloneDXReporter) Extension() string {
	return "json"
}

type CycloneDXOutput struct {
	BomFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	Metadata     CycloneDXMetadata     `json:"metadata"`
	Components   []CycloneDXComponent  `json:"components,omitempty"`
	Dependencies []CycloneDXDependency `json:"dependencies,omitempty"`
}

type CycloneDXMetadata struct {
	Timestamp string          `json:"timestamp"`
	Tools     []CycloneDXTool `json:"tools"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	Type    string           `json:"type"`
	BomRef  string           `json:"bom-ref"`
	Name    string           `json:"name"`
	Version string           `json:"version,omitempty"`
	Package CycloneDXPackage `json:"package,omitempty"`
}

type CycloneDXPackage struct {
	PURL string `json:"purl"`
}

type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func (r *CycloneDXReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := CycloneDXOutput{
		BomFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  "Iris",
					Name:    "iris",
					Version: "1.1.0",
				},
			},
		},
	}

	vulnerabilityMap := make(map[string]bool)
	for _, result := range results {
		for _, f := range result.Findings {
			if f.ScanType == core.ScanTypeSCA && !vulnerabilityMap[f.RuleID] {
				component := CycloneDXComponent{
					Type:   "library",
					BomRef: f.RuleID,
					Name:   f.Title,
				}
				output.Components = append(output.Components, component)
				vulnerabilityMap[f.RuleID] = true
			}
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

func init() {
	_ = fmt.Sprintf
}
