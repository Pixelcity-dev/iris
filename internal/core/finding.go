package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

type ScanType string

const (
	ScanTypeSAST      ScanType = "sast"
	ScanTypeSCA       ScanType = "sca"
	ScanTypeSecrets   ScanType = "secrets"
	ScanTypeIAC       ScanType = "iac"
	ScanTypeContainer ScanType = "container"
	ScanTypeDAST      ScanType = "dast"
	ScanTypeNetwork   ScanType = "network"
	ScanTypeLicense   ScanType = "license"
	ScanTypeWebScan   ScanType = "webscan"
	ScanTypeFormat    ScanType = "format"
	ScanTypeBuildTest ScanType = "buildtest"
)

type TargetKind string

const (
	TargetFS      TargetKind = "fs"
	TargetRepo    TargetKind = "repo"
	TargetImage   TargetKind = "image"
	TargetK8s     TargetKind = "k8s"
	TargetSBOM    TargetKind = "sbom"
	TargetURL     TargetKind = "url"
	TargetNetwork TargetKind = "network"
)

type Target struct {
	Kind    TargetKind             `json:"kind"`
	URI     string                 `json:"uri"`
	Options map[string]interface{} `json:"options,omitempty"`
}

type Finding struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	ScanType    ScanType               `json:"scan_type"`
	Severity    Severity               `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	File        string                 `json:"file,omitempty"`
	Line        int                    `json:"line,omitempty"`
	Column      int                    `json:"column,omitempty"`
	EndLine     int                    `json:"end_line,omitempty"`
	EndColumn   int                    `json:"end_column,omitempty"`
	Code        string                 `json:"code,omitempty"`
	Fix         string                 `json:"fix,omitempty"`
	References  []string               `json:"references,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Confidence  float64                `json:"confidence"`
	Fingerprint string                 `json:"fingerprint"`
	Timestamp   time.Time              `json:"timestamp"`
}

func (f *Finding) GenerateFingerprint() {
	data := fmt.Sprintf("%s:%s:%s:%s:%d:%d",
		f.RuleID, f.File, f.Title, f.Code, f.Line, f.Column)
	hash := sha256.Sum256([]byte(data))
	f.Fingerprint = fmt.Sprintf("%x", hash[:8])
}

func (f *Finding) ToJSON() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

type ScanResult struct {
	Target    Target    `json:"target"`
	Findings  []Finding `json:"findings"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Duration  float64   `json:"duration_seconds"`
	Scanner   string    `json:"scanner"`
	Error     string    `json:"error,omitempty"`
}

func (r *ScanResult) AddFinding(f Finding) {
	f.GenerateFingerprint()
	f.Timestamp = time.Now()
	r.Findings = append(r.Findings, f)
}

func (r *ScanResult) FilterBySeverity(minSeverity Severity) []Finding {
	var filtered []Finding
	for _, f := range r.Findings {
		if f.Severity >= minSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

type ScanSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByType        map[string]int `json:"by_type"`
	ByCategory    map[string]int `json:"by_category"`
	FilesScanned  int            `json:"files_scanned"`
	Duration      float64        `json:"duration_seconds"`
}

func NewScanSummary(results []ScanResult) ScanSummary {
	summary := ScanSummary{
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
		ByCategory: make(map[string]int),
	}

	for _, r := range results {
		for _, f := range r.Findings {
			summary.TotalFindings++
			summary.BySeverity[f.Severity.String()]++
			summary.ByType[string(f.ScanType)]++
			if f.Category != "" {
				summary.ByCategory[f.Category]++
			}
		}
		summary.Duration += r.Duration
	}

	return summary
}
