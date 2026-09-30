package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type GitLabReporter struct{}

func (r *GitLabReporter) Name() string {
	return "gitlab"
}

func (r *GitLabReporter) Extension() string {
	return "json"
}

type GitLabReport struct {
	Schema          string         `json:"schema"`
	Version         string         `json:"version"`
	ScanType        string         `json:"scan_type"`
	ScanInfo        GitLabScanInfo `json:"scan_info"`
	Vulnerabilities []GitLabVuln   `json:"vulnerabilities,omitempty"`
}

type GitLabScanInfo struct {
	ScanType  string        `json:"scan_type"`
	Scanner   GitLabScanner `json:"scanner"`
	Timestamp string        `json:"timestamp"`
}

type GitLabScanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GitLabVuln struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Name        string             `json:"name"`
	Message     string             `json:"message"`
	Description string             `json:"description"`
	Severity    string             `json:"severity"`
	Solution    string             `json:"solution,omitempty"`
	Identifiers []GitLabIdentifier `json:"identifiers"`
	Location    GitLabLocation     `json:"location"`
}

type GitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GitLabLocation struct {
	File string `json:"file"`
}

func (r *GitLabReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := GitLabReport{
		Schema:   "https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/assets/javascripts/security_dashboard/schemas/gl-sast-report-format.json",
		Version:  "15.0.0",
		ScanType: "sast",
		ScanInfo: GitLabScanInfo{
			ScanType: "sast",
			Scanner: GitLabScanner{
				ID:      "iris",
				Name:    "Iris",
				Version: "1.1.0",
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	for _, result := range results {
		for _, f := range result.Findings {
			vuln := GitLabVuln{
				ID:          f.Fingerprint,
				Category:    f.Category,
				Name:        f.Title,
				Message:     f.Description,
				Description: f.Description,
				Severity:    mapGitLabSeverity(f.Severity),
				Solution:    f.Fix,
				Location: GitLabLocation{
					File: f.File,
				},
			}

			if f.References != nil {
				for _, ref := range f.References {
					vuln.Identifiers = append(vuln.Identifiers, GitLabIdentifier{
						Type:  "url",
						Name:  "Reference",
						Value: ref,
					})
				}
			}

			output.Vulnerabilities = append(output.Vulnerabilities, vuln)
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

func mapGitLabSeverity(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "Critical"
	case core.SeverityHigh:
		return "High"
	case core.SeverityMedium:
		return "Medium"
	case core.SeverityLow:
		return "Low"
	default:
		return "Info"
	}
}

func init() {
	_ = fmt.Sprintf
}
