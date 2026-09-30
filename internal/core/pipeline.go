package core

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Progress receives lifecycle events while the pipeline runs scanners.
type Progress interface {
	// OnScannerStart is called when a scanner begins.
	OnScannerStart(scanType ScanType, name string)
	// OnScannerDone is called when a scanner finished with findings count and duration.
	OnScannerDone(scanType ScanType, name string, findings int, duration time.Duration)
	// OnScannerError is called when a scanner returned an error.
	OnScannerError(scanType ScanType, name string, err error, duration time.Duration)
}

type Pipeline struct {
	registry *ScannerRegistry
	rules    *RuleEngine
	filter   *FindingFilter
	dedup    *Deduplicator
	progress Progress
}

func NewPipeline(registry *ScannerRegistry, rules *RuleEngine) *Pipeline {
	return &Pipeline{
		registry: registry,
		rules:    rules,
		filter:   NewFindingFilter(),
		dedup:    NewDeduplicator(),
	}
}

// SetProgress attaches a progress listener (e.g. the CLI spinner).
func (p *Pipeline) SetProgress(pv Progress) { p.progress = pv }

// SetFilter sets the finding filter applied after each scanner runs.
func (p *Pipeline) SetFilter(f *FindingFilter) { p.filter = f }

func (p *Pipeline) Scan(ctx context.Context, target Target, scanTypes []ScanType) ([]ScanResult, error) {
	scanners := p.registry.GetByTypes(scanTypes)
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners available for requested types")
	}

	var (
		mu      sync.Mutex
		results []ScanResult
		wg      sync.WaitGroup
	)

	for _, scanner := range scanners {
		wg.Add(1)
		go func(s Scanner) {
			defer wg.Done()

			start := time.Now()
			if p.progress != nil {
				p.progress.OnScannerStart(s.Type(), s.Name())
			}
			rules := p.rules.GetRulesForScanner(s.Type())

			findings, err := s.Scan(ctx, target, rules)
			duration := time.Since(start)

			result := ScanResult{
				Target:    target,
				Scanner:   s.Name(),
				StartTime: start,
				EndTime:   time.Now(),
				Duration:  duration.Seconds(),
			}

			if err != nil {
				result.Error = err.Error()
				if p.progress != nil {
					p.progress.OnScannerError(s.Type(), s.Name(), err, duration)
				}
			} else if p.progress != nil {
				p.progress.OnScannerDone(s.Type(), s.Name(), len(findings), duration)
			}

			for _, f := range findings {
				f.ScanType = s.Type()
				result.AddFinding(f)
			}

			result.Findings = p.dedup.Deduplicate(result.Findings)
			result.Findings = p.filter.Filter(result.Findings)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(scanner)
	}

	wg.Wait()

	return results, nil
}

func (p *Pipeline) ScanAll(ctx context.Context, target Target) ([]ScanResult, error) {
	var scanTypes []ScanType
	for _, s := range p.registry.GetAll() {
		if s.IsEnabled() {
			scanTypes = append(scanTypes, s.Type())
		}
	}
	return p.Scan(ctx, target, scanTypes)
}

type FindingFilter struct {
	MinSeverity        Severity
	ExcludedRules      []string
	IncludedRules      []string
	ExcludedFiles      []string
	IncludedFiles      []string
	ExcludedCategories []string
}

func NewFindingFilter() *FindingFilter {
	return &FindingFilter{
		MinSeverity: SeverityInfo,
	}
}

func (f *FindingFilter) Filter(findings []Finding) []Finding {
	if f == nil {
		return findings
	}

	var filtered []Finding
	for _, finding := range findings {
		if !f.shouldInclude(finding) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func (f *FindingFilter) shouldInclude(finding Finding) bool {
	if finding.Severity < f.MinSeverity {
		return false
	}

	if len(f.ExcludedRules) > 0 {
		for _, rule := range f.ExcludedRules {
			if finding.RuleID == rule {
				return false
			}
		}
	}

	if len(f.IncludedRules) > 0 {
		found := false
		for _, rule := range f.IncludedRules {
			if finding.RuleID == rule {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.ExcludedFiles) > 0 {
		for _, file := range f.ExcludedFiles {
			if finding.File == file {
				return false
			}
		}
	}

	if len(f.ExcludedCategories) > 0 {
		for _, cat := range f.ExcludedCategories {
			if finding.Category == cat {
				return false
			}
		}
	}

	return true
}

type Deduplicator struct {
	seen map[string]bool
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

func (d *Deduplicator) Deduplicate(findings []Finding) []Finding {
	d.seen = make(map[string]bool)
	var unique []Finding

	for _, f := range findings {
		if f.Fingerprint == "" {
			f.GenerateFingerprint()
		}
		if !d.seen[f.Fingerprint] {
			d.seen[f.Fingerprint] = true
			unique = append(unique, f)
		}
	}

	return unique
}
