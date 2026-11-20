package sca

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type SCAScanner struct {
	core.BaseScanner
	name string
}

func NewSCAScanner() *SCAScanner {
	return &SCAScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "sca",
	}
}

func (s *SCAScanner) Name() string {
	return s.name
}

func (s *SCAScanner) Type() core.ScanType {
	return core.ScanTypeSCA
}

func (s *SCAScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

// manifestScanners maps a manifest file name to the parser that understands
// it. Keeping this as one list means the directory is walked once instead of
// once per ecosystem, and output order is stable.
var manifestScanners = map[string]func(string) ([]core.Finding, error){
	"go.mod":           scanGoModules,
	"package.json":     scanNPM,
	"requirements.txt": scanPython,
	"Pipfile":          scanPython,
	"pom.xml":          scanMaven,
	"build.gradle":     scanGradle,
	"build.gradle.kts": scanGradle,
	"Cargo.toml":       scanCargo,
	"Gemfile":          scanRuby,
	"composer.json":    scanPHP,
}

func (s *SCAScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var paths []string

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
		base := filepath.Base(path)
		if _, ok := manifestScanners[base]; ok || strings.HasSuffix(base, ".csproj") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(paths)

	var findings []core.Finding
	for _, path := range paths {
		scanner := manifestScanners[filepath.Base(path)]
		if scanner == nil {
			scanner = scanDotNet
		}
		f, err := scanner(path)
		if err != nil {
			continue
		}
		findings = append(findings, f...)
	}

	return findings, nil
}

func scanGoModules(path string) ([]core.Finding, error) {
	var findings []core.Finding

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// go.mod lists dependencies either inline ("require x v1.0.0") or in a
	// parenthesised block. Handling only the inline form missed nearly every
	// real module.
	inRequireBlock := false
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inRequireBlock {
			if line == ")" {
				inRequireBlock = false
				continue
			}
			addGoDependency(&findings, path, line, i+1)
			continue
		}
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(line, "require ") {
			addGoDependency(&findings, path, strings.TrimSpace(strings.TrimPrefix(line, "require")), i+1)
		}
	}

	return findings, nil
}

func addGoDependency(findings *[]core.Finding, path, line string, lineNo int) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	*findings = append(*findings, core.Finding{
		RuleID:      "sca-go-dependency",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "Go Dependency Detected",
		Description: "Dependency: " + parts[0],
		File:        path,
		Line:        lineNo,
		Code:        line,
		Confidence:  1.0,
	})
}

func scanNPM(path string) ([]core.Finding, error) {
	var findings []core.Finding

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	if strings.Contains(content, "dependencies") {
		findings = append(findings, core.Finding{
			RuleID:      "sca-npm-package",
			Severity:    core.SeverityInfo,
			Category:    "dependency",
			Title:       "NPM Package Detected",
			Description: "package.json found with dependencies",
			File:        path,
			Confidence:  1.0,
		})
	}

	return findings, nil
}

func scanPython(path string) ([]core.Finding, error) {
	var findings []core.Finding

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "==") {
			parts := strings.Split(line, "==")
			if len(parts) == 2 {
				findings = append(findings, core.Finding{
					RuleID:      "sca-python-dependency",
					Severity:    core.SeverityInfo,
					Category:    "dependency",
					Title:       "Python Dependency Detected",
					Description: "Package: " + strings.TrimSpace(parts[0]),
					File:        path,
					Line:        i + 1,
					Code:        line,
					Confidence:  1.0,
				})
			}
		}
	}

	return findings, nil
}

func scanMaven(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-maven-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "Maven Project Detected",
		Description: "pom.xml found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}

func scanGradle(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-gradle-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "Gradle Project Detected",
		Description: "build.gradle found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}

func scanCargo(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-cargo-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "Cargo Project Detected",
		Description: "Cargo.toml found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}

func scanRuby(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-ruby-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "Ruby Project Detected",
		Description: "Gemfile found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}

func scanPHP(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-php-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       "PHP Project Detected",
		Description: "composer.json found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}

func scanDotNet(path string) ([]core.Finding, error) {
	return []core.Finding{{
		RuleID:      "sca-dotnet-project",
		Severity:    core.SeverityInfo,
		Category:    "dependency",
		Title:       ".NET Project Detected",
		Description: "Project file found",
		File:        path,
		Confidence:  1.0,
	}}, nil
}
