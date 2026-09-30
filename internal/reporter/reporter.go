package reporter

import (
	"github.com/Pixelcity-dev/Iris/internal/core"
)

type ReportOptions struct {
	Format   string
	Output   string
	Color    bool
	Template string
}

type Reporter interface {
	Name() string
	Extension() string
	Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error)
}

var reporters = map[string]Reporter{
	"table":     &TableReporter{},
	"json":      &JSONReporter{},
	"sarif":     &SARIFReporter{},
	"cyclonedx": &CycloneDXReporter{},
	"spdx":      &SPDXReporter{},
	"html":      &HTMLReporter{},
	"csv":       &CSVReporter{},
	"junit":     &JUnitReporter{},
	"github":    &GitHubReporter{},
	"gitlab":    &GitLabReporter{},
}

func GetReporter(format string) Reporter {
	if r, ok := reporters[format]; ok {
		return r
	}
	return nil
}

func RegisterReporter(format string, r Reporter) {
	reporters[format] = r
}

func ListReporters() []string {
	var formats []string
	for f := range reporters {
		formats = append(formats, f)
	}
	return formats
}
