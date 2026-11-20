package sast

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

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
			if core.ShouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		if !isAnalyzable(path) || info.Size() > core.MaxScanFileBytes {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lang := detectLanguage(path)
		relPath, _ := filepath.Rel(target.URI, path)

		for _, rule := range rules {
			if !languageMatches(rule.Language, lang) {
				continue
			}

			findings = append(findings, analyzeFile(relPath, string(data), rule, lang)...)
		}

		return nil
	})

	return findings, err
}

var analyzableExtensions = map[string]bool{
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

func isAnalyzable(path string) bool {
	return analyzableExtensions[filepath.Ext(path)]
}

// languageMatches reports whether a rule applies to a file language. A rule
// tagged generic (or tagged with no language) applies everywhere; the built-in
// rules are all generic, and an exact comparison would silently skip every one
// of them.
func languageMatches(ruleLang, fileLang string) bool {
	switch strings.ToLower(strings.TrimSpace(ruleLang)) {
	case "", "generic", "any", "all", "*", "unknown":
		return true
	}
	return strings.EqualFold(ruleLang, fileLang)
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
		// One finding per line and rule: repeated matches on the same line
		// ("MD5 ... SHA1") describe the same location and only add noise.
		matches := matchRule(line, rule)
		if len(matches) == 0 {
			continue
		}
		finding := core.Finding{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Category:    rule.Category,
			Title:       rule.Name,
			Description: rule.Description,
			File:        path,
			Line:        i + 1,
			Column:      matches[0][0] + 1,
			Code:        strings.TrimSpace(line),
			Fix:         rule.Fix,
			References:  rule.References,
			Tags:        rule.Tags,
			Confidence:  0.8,
		}
		finding.GenerateFingerprint()
		findings = append(findings, finding)
	}

	return findings
}

// patternCache stores compiled rule patterns. Scanners run once per scan, but
// a rule is matched against every line of every file, so recompiling per line
// would dominate scan time.
var patternCache sync.Map // pattern string -> *regexp.Regexp (nil on compile failure)

func compilePattern(pattern string) *regexp.Regexp {
	if cached, ok := patternCache.Load(pattern); ok {
		re, _ := cached.(*regexp.Regexp)
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	patternCache.Store(pattern, re)
	return re
}

// matchRule returns the byte offsets of each match of the rule pattern in the
// line. Rules are regular expressions (alternation with "|"), with "||" also
// accepted for older custom rules. A pattern that does not compile falls back
// to a literal substring match so a malformed custom rule degrades to a
// weaker check instead of silently disabling itself.
func matchRule(line string, rule core.Rule) [][]int {
	original := strings.TrimSpace(rule.Pattern)
	if original == "" {
		return nil
	}
	pattern := strings.ReplaceAll(original, "||", "|")

	if re := compilePattern(pattern); re != nil {
		return re.FindAllStringIndex(line, -1)
	}

	// Provide a weaker check rather than silently dropping a custom rule
	// whose pattern is not valid regexp syntax.
	for _, literal := range strings.Split(original, "||") {
		literal = strings.TrimSpace(literal)
		if literal == "" {
			continue
		}
		if idx := strings.Index(line, literal); idx >= 0 {
			return [][]int{{idx, idx + len(literal)}}
		}
	}
	return nil
}
