package format

import (
	"bytes"
	"context"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type FormatScanner struct {
	core.BaseScanner
	name      string
	maxLength int
}

func NewFormatScanner() *FormatScanner {
	return &FormatScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "format",
		maxLength:   120,
	}
}

func (s *FormatScanner) Name() string { return s.name }

func (s *FormatScanner) Type() core.ScanType { return core.ScanTypeFormat }

func (s *FormatScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

func (s *FormatScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	err := filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "bin" || name == ".next" || name == ".iris" {
				return filepath.SkipDir
			}
			return nil
		}
		if !isFormattable(path) {
			return nil
		}
		// Respect .gitignore-like excludes: skip large binaries
		if info.Size() > 2*1024*1024 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		relPath, _ := filepath.Rel(target.URI, path)
		if relPath == "." {
			relPath = filepath.Base(path)
		}
		content := string(data)
		findings = append(findings, checkFile(relPath, content, s.maxLength)...)

		// Go fmt check for .go files
		if strings.HasSuffix(path, ".go") {
			if fts := checkGoFmt(relPath, content); len(fts) > 0 {
				findings = append(findings, fts...)
			}
		}
		return nil
	})

	return findings, err
}

func isFormattable(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := filepath.Base(path)
	// Allow-list
	allowExt := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".py": true, ".rb": true, ".php": true, ".java": true, ".rs": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".kt": true, ".swift": true,
		".css": true, ".scss": true, ".html": true, ".vue": true, ".svelte": true,
		".json": true, ".yaml": true, ".yml": true, ".toml": true, ".md": true, ".txt": true, ".env": true,
		".sh": true, ".bash": true, ".zsh": true, ".mjs": true, ".cjs": true,
		".sql": true, ".graphql": true,
	}
	if allowExt[ext] {
		return true
	}
	if ext == "" && base == ".editorconfig" {
		return true
	}
	allowBase := map[string]bool{
		"Dockerfile": true, "Makefile": true, "Justfile": true,
	}
	if allowBase[base] {
		return true
	}
	// Also consider files without extension but known
	if allowBase[strings.ToUpper(base)] {
		return true
	}
	return false
}

func checkFile(path, content string, maxLen int) []core.Finding {
	var findings []core.Finding
	lines := strings.Split(content, "\n")
	hasTrailing := false
	hasCRLF := false
	if strings.Contains(content, "\r\n") {
		hasCRLF = true
		findings = append(findings, core.Finding{
			RuleID:      "fmt-crlf-line-ending",
			Severity:    core.SeverityLow,
			Category:    "formatting",
			Title:       "CRLF line endings",
			Description: "File uses Windows CRLF; prefer LF",
			File:        path,
			Line:        1,
			Code:        "\\r\\n detected",
			Fix:         "Convert to LF: sed -i 's/\\r$//' file or enable .editorconfig end_of_line=lf",
			Confidence:  0.9,
		})
	}
	// Check missing EOF newline - only if not already CRLF issue? Still report
	if len(content) > 0 && !strings.HasSuffix(content, "\n") {
		findings = append(findings, core.Finding{
			RuleID:      "fmt-missing-eof-newline",
			Severity:    core.SeverityLow,
			Category:    "formatting",
			Title:       "Missing newline at end of file",
			Description: "File does not end with a newline",
			File:        path,
			Line:        len(lines),
			Code:        lines[len(lines)-1],
			Fix:         "Add newline at EOF",
			Confidence:  1.0,
		})
	}

	for i, line := range lines {
		// Skip last empty line after split (EOF newline creates extra "")
		if i == len(lines)-1 && line == "" {
			continue
		}
		// Trailing whitespace
		if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
			trimmed := strings.TrimRightFunc(line, unicode.IsSpace)
			col := len(trimmed) + 1
			hasTrailing = true
			findings = append(findings, core.Finding{
				RuleID:      "fmt-trailing-whitespace",
				Severity:    core.SeverityInfo,
				Category:    "formatting",
				Title:       "Trailing whitespace",
				Description: "Line has trailing spaces/tabs",
				File:        path,
				Line:        i + 1,
				Column:      col,
				Code:        truncate(line, 120),
				Fix:         "Remove trailing whitespace",
				Confidence:  1.0,
			})
		}
		// Mixed indentation: has tab and leading spaces? Simple check
		if strings.HasPrefix(line, " ") && strings.Contains(line, "\t") {
			// Count leading whitespaces
			leading := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			if strings.Contains(leading, " ") && strings.Contains(leading, "\t") {
				findings = append(findings, core.Finding{
					RuleID:      "fmt-mixed-indentation",
					Severity:    core.SeverityInfo,
					Category:    "style",
					Title:       "Mixed indentation (spaces and tabs)",
					Description: "Line uses both spaces and tabs for indentation",
					File:        path,
					Line:        i + 1,
					Code:        truncate(line, 80),
					Fix:         "Use consistent indentation (gofmt uses tabs for Go, spaces for others)",
					Confidence:  0.7,
				})
			}
		}
		// Line too long — skip for markup/data where long lines are normal
		if len(line) > maxLen && strings.TrimSpace(line) != "" && !isLongLineException(line) && !isMarkupFile(path) {
			findings = append(findings, core.Finding{
				RuleID:      "fmt-line-too-long",
				Severity:    core.SeverityInfo,
				Category:    "style",
				Title:       "Line too long",
				Description: "Line exceeds 120 characters",
				File:        path,
				Line:        i + 1,
				Column:      maxLen + 1,
				Code:        truncate(line, 120) + " …",
				Fix:         "Break line or reduce length to <=120",
				Confidence:  0.6,
			})
		}
		// Also check for multiple consecutive blank lines (>1)
		if i > 0 && strings.TrimSpace(line) == "" && strings.TrimSpace(lines[i-1]) == "" {
			// Look ahead to avoid duplicate reporting for 3+ blanks: only report second blank
			if i == 1 || strings.TrimSpace(lines[i-2]) != "" {
				findings = append(findings, core.Finding{
					RuleID:      "fmt-consecutive-blank-lines",
					Severity:    core.SeverityInfo,
					Category:    "style",
					Title:       "Consecutive blank lines",
					Description: "Multiple consecutive blank lines",
					File:        path,
					Line:        i + 1,
					Code:        "(blank)",
					Fix:         "Reduce to single blank line",
					Confidence:  0.8,
				})
			}
		}
	}
	// Avoid duplicate hasCRLF/hasTrailing vars unused
	_ = hasTrailing
	_ = hasCRLF
	return findings
}

func isLongLineException(line string) bool {
	trim := strings.TrimSpace(line)
	// Allow long lines for URLs, import statements, or generated files
	if strings.Contains(trim, "http://") || strings.Contains(trim, "https://") {
		return true
	}
	if strings.HasPrefix(trim, "import ") && strings.Contains(trim, "github.com") {
		return true
	}
	if strings.HasPrefix(trim, "//go:") {
		return true
	}
	// Generated or minified markers
	if strings.Contains(trim, "Code generated") || strings.Contains(trim, "DO NOT EDIT") {
		return true
	}
	return false
}

func isMarkupFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	markup := map[string]bool{".html": true, ".css": true, ".scss": true, ".json": true, ".yaml": true, ".yml": true, ".md": true, ".svg": true}
	return markup[ext]
}

func checkGoFmt(path, content string) []core.Finding {
	fset := token.NewFileSet()
	// Parse with parser mode that tolerates some errors but we want to know if unparsable -> skip
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments)
	if err != nil {
		// If parse fails, still try format? Skip gofmt check and report syntax?
		return nil
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, file); err != nil {
		return nil
	}
	formatted := buf.String()
	if formatted != content {
		// Find first differing line
		origLines := strings.Split(content, "\n")
		fmtLines := strings.Split(formatted, "\n")
		diffLine := 1
		for i := 0; i < len(origLines) && i < len(fmtLines); i++ {
			if origLines[i] != fmtLines[i] {
				diffLine = i + 1
				break
			}
		}
		if len(origLines) != len(fmtLines) && diffLine == 1 {
			// Fallback to length diff
			if len(fmtLines) < len(origLines) {
				diffLine = len(fmtLines)
			}
		}
		return []core.Finding{{
			RuleID:      "fmt-gofmt",
			Severity:    core.SeverityLow,
			Category:    "formatting",
			Title:       "Go file not formatted (gofmt)",
			Description: "File differs from gofmt output",
			File:        path,
			Line:        diffLine,
			Code:        truncate(fmtLines[diffLine-1], 120),
			Fix:         "Run gofmt -w or iris fmt --fix",
			Confidence:  1.0,
		}}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// FixFile applies auto-fix for formatting issues: trailing whitespace, EOF newline, CRLF, and gofmt.
// Returns true if file was changed.
func FixFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := string(data)
	original := content

	// Normalize CRLF to LF
	if strings.Contains(content, "\r\n") {
		content = strings.ReplaceAll(content, "\r\n", "\n")
		content = strings.ReplaceAll(content, "\r", "\n")
	}
	lines := strings.Split(content, "\n")
	fixedLines := make([]string, len(lines))
	for i, line := range lines {
		// Remove trailing whitespace
		fixedLines[i] = strings.TrimRightFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		// Collapse consecutive blank lines to one? For fmt --fix, we remove extra blanks
		if i > 0 && fixedLines[i] == "" && fixedLines[i-1] == "" {
			// Mark for removal by setting to sentinel, later filter
			fixedLines[i] = "__REMOVE_BLANK__"
		}
	}
	// Filter removed blanks
	var filtered []string
	for _, l := range fixedLines {
		if l == "__REMOVE_BLANK__" {
			continue
		}
		filtered = append(filtered, l)
	}
	content = strings.Join(filtered, "\n")
	// Ensure single newline at EOF
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	// Ensure no double newline at EOF? Keep single
	for strings.HasSuffix(content, "\n\n") {
		content = strings.TrimSuffix(content, "\n")
	}
	content += "\n"
	// Actually we want exactly one newline: the loop above ensures one, but we added extra. Fix:
	// After ensuring suffix, we have at least one. Remove duplicate logic: simplify
	// Re-normalize: ensure ends with single \n
	content = strings.TrimRight(content, "\n") + "\n"

	// For Go files, run gofmt
	if strings.HasSuffix(path, ".go") {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, content, parser.ParseComments)
		if err == nil {
			var buf bytes.Buffer
			if err := format.Node(&buf, fset, f); err == nil {
				content = buf.String()
			}
		}
	}

	if content == original {
		return false, nil
	}
	// Preserve file mode
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	mode := info.Mode()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return false, err
	}
	return true, nil
}
