package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type SARIFReporter struct{}

func (r *SARIFReporter) Name() string {
	return "sarif"
}

func (r *SARIFReporter) Extension() string {
	return "sarif"
}

type SARIFOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     SARIFText   `json:"shortDescription"`
	FullDescription      SARIFText   `json:"fullDescription,omitempty"`
	HelpURI              string      `json:"helpUri,omitempty"`
	DefaultConfiguration SARIFConfig `json:"defaultConfiguration,omitempty"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFConfig struct {
	Level string `json:"level,omitempty"`
}

type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

func (r *SARIFReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := SARIFOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	for _, result := range results {
		run := SARIFRun{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "iris",
					Version:        "1.1.0",
					InformationURI: "https://iris.pixelcity.dev",
				},
			},
		}

		ruleMap := make(map[string]bool)
		for _, f := range result.Findings {
			if !ruleMap[f.RuleID] {
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, SARIFRule{
					ID:   f.RuleID,
					Name: f.Title,
					ShortDescription: SARIFText{
						Text: f.Description,
					},
					DefaultConfiguration: SARIFConfig{
						Level: mapLevel(f.Severity),
					},
				})
				ruleMap[f.RuleID] = true
			}

			sarifResult := SARIFResult{
				RuleID: f.RuleID,
				Level:  mapLevel(f.Severity),
				Message: SARIFMessage{
					Text: f.Description,
				},
				Properties: map[string]interface{}{
					"severity":    f.Severity.String(),
					"category":    f.Category,
					"confidence":  f.Confidence,
					"fingerprint": f.Fingerprint,
				},
			}

			if f.File != "" {
				sarifResult.Locations = []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: f.File,
							},
							Region: SARIFRegion{
								StartLine:   f.Line,
								StartColumn: f.Column,
								EndLine:     f.EndLine,
								EndColumn:   f.EndColumn,
							},
						},
					},
				}
			}

			run.Results = append(run.Results, sarifResult)
		}

		output.Runs = append(output.Runs, run)
	}

	return json.MarshalIndent(output, "", "  ")
}

func mapLevel(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	case core.SeverityLow, core.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}

func init() {
	_ = time.Now()
	_ = fmt.Sprintf
}
