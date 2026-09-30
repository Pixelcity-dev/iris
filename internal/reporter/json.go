package reporter

import (
	"encoding/json"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type JSONReporter struct{}

func (r *JSONReporter) Name() string {
	return "json"
}

func (r *JSONReporter) Extension() string {
	return "json"
}

type JSONOutput struct {
	Version   string            `json:"version"`
	Timestamp string            `json:"timestamp"`
	Results   []core.ScanResult `json:"results"`
	Summary   core.ScanSummary  `json:"summary"`
}

func (r *JSONReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := JSONOutput{
		Version: "1.1.0",
		Summary: core.NewScanSummary(results),
		Results: results,
	}

	return json.MarshalIndent(output, "", "  ")
}
