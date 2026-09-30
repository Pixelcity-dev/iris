package sast

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type SASTScanner struct {
	core.BaseScanner
	name string
}

func NewSASTScanner() *SASTScanner {
	return &SASTScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "sast",
	}
}

func (s *SASTScanner) Name() string {
	return s.name
}

func (s *SASTScanner) Type() core.ScanType {
	return core.ScanTypeSAST
}

func (s *SASTScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

func (s *SASTScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	err := filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if !isAnalyzable(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lang := detectLanguage(path)
		relPath, _ := filepath.Rel(target.URI, path)

		for _, rule := range rules {
			if rule.Language != "" && !strings.EqualFold(rule.Language, lang) {
				continue
			}

			findings = append(findings, analyzeFile(relPath, string(data), rule, lang)...)
		}

		return nil
	})

	return findings, err
}

func isAnalyzable(path string) bool {
	extensions := map[string]bool{
		".go":    true,
		".py":    true,
		".js":    true,
		".ts":    true,
		".jsx":   true,
		".tsx":   true,
		".java":  true,
		".rs":    true,
		".rb":    true,
		".php":   true,
		".cs":    true,
		".c":     true,
		".cpp":   true,
		".h":     true,
		".hpp":   true,
		".swift": true,
		".kt":    true,
	}

	ext := filepath.Ext(path)
	return extensions[ext]
}

func detectLanguage(path string) string {
	ext := filepath.Ext(path)
	langMap := map[string]string{
		".go":    "go",
		".py":    "python",
		".js":    "javascript",
		".ts":    "typescript",
		".jsx":   "javascript",
		".tsx":   "typescript",
		".java":  "java",
		".rs":    "rust",
		".rb":    "ruby",
		".php":   "php",
		".cs":    "csharp",
		".c":     "c",
		".cpp":   "cpp",
		".h":     "c",
		".hpp":   "cpp",
		".swift": "swift",
		".kt":    "kotlin",
	}

	if lang, ok := langMap[ext]; ok {
		return lang
	}
	return "unknown"
}

func analyzeFile(path, content string, rule core.Rule, lang string) []core.Finding {
	var findings []core.Finding

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if matchRule(line, rule) {
			finding := core.Finding{
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Title:       rule.Name,
				Description: rule.Description,
				File:        path,
				Line:        i + 1,
				Code:        strings.TrimSpace(line),
				Fix:         rule.Fix,
				References:  rule.References,
				Tags:        rule.Tags,
				Confidence:  0.8,
			}
			finding.GenerateFingerprint()
			findings = append(findings, finding)
		}
	}

	return findings
}

func matchRule(line string, rule core.Rule) bool {
	if rule.Pattern == "" {
		return false
	}

	patterns := strings.Split(rule.Pattern, "||")
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}
