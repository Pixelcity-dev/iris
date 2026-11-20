package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

var severityColors = map[Severity]string{
	SeverityInfo:     "\033[36m",
	SeverityLow:      "\033[33m",
	SeverityMedium:   "\033[93m",
	SeverityHigh:     "\033[31m",
	SeverityCritical: "\033[1;31m",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "UNKNOWN"
}

func (s Severity) Color() string {
	if color, ok := severityColors[s]; ok {
		return color
	}
	return ""
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

// UnmarshalYAML accepts severity names ("critical") in rule files, matching
// the JSON representation used by findings.
func (s *Severity) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return err
	}
	*s = ParseSeverity(str)
	return nil
}

func (s Severity) MarshalYAML() (interface{}, error) {
	return s.String(), nil
}

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "INFO", "INFORMATIONAL":
		return SeverityInfo
	case "LOW":
		return SeverityLow
	case "MEDIUM", "MED":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL", "CRIT":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

func ParseSeverities(s string) []Severity {
	parts := strings.Split(s, ",")
	var severities []Severity
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			severities = append(severities, ParseSeverity(p))
		}
	}
	return severities
}

func (s Severity) Weight() int {
	return int(s)
}

func RiskScore(findings []Finding) (score int, level string) {
	weights := map[Severity]int{SeverityCritical: 40, SeverityHigh: 10, SeverityMedium: 3, SeverityLow: 1, SeverityInfo: 0}
	for _, f := range findings {
		score += weights[f.Severity]
	}
	switch {
	case score == 0:
		return 0, "None"
	case score < 5:
		return score, "Low"
	case score < 20:
		return score, "Medium"
	case score < 50:
		return score, "High"
	default:
		return score, "Critical"
	}
}

func FormatSeverity(s Severity) string {
	color := s.Color()
	reset := "\033[0m"
	if color == "" {
		return fmt.Sprintf("%-10s", s.String())
	}
	return fmt.Sprintf("%s%-10s%s", color, s.String(), reset)
}
