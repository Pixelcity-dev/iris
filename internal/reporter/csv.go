package reporter

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type CSVReporter struct{}

func (r *CSVReporter) Name() string {
	return "csv"
}

func (r *CSVReporter) Extension() string {
	return "csv"
}

func (r *CSVReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	var sb strings.Builder
	writer := csv.NewWriter(&sb)

	header := []string{"ID", "Rule ID", "Severity", "Category", "Scan Type", "Title", "Description", "File", "Line", "Column", "Fix", "References", "Confidence"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, result := range results {
		for _, f := range result.Findings {
			refs := strings.Join(f.References, "; ")
			row := []string{
				f.ID,
				f.RuleID,
				f.Severity.String(),
				f.Category,
				string(f.ScanType),
				f.Title,
				f.Description,
				f.File,
				strconv.Itoa(f.Line),
				strconv.Itoa(f.Column),
				f.Fix,
				refs,
				fmt.Sprintf("%.2f", f.Confidence),
			}
			if err := writer.Write(row); err != nil {
				return nil, fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to flush CSV: %w", err)
	}

	return []byte(sb.String()), nil
}
