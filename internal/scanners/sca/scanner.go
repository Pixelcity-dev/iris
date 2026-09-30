package sca

import (
	"context"
	"os"
	"path/filepath"
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

func (s *SCAScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	ecosystems := map[string]func(string) ([]core.Finding, error){
		"go.mod":           scanGoModules,
		"package.json":     scanNPM,
		"requirements.txt": scanPython,
		"Pipfile":          scanPython,
		"pom.xml":          scanMaven,
		"build.gradle":     scanGradle,
		"Cargo.toml":       scanCargo,
		"Gemfile":          scanRuby,
		"composer.json":    scanPHP,
		"*.csproj":         scanDotNet,
	}

	for pattern, scanner := range ecosystems {
		if strings.Contains(pattern, "*") {
			ext := strings.TrimPrefix(pattern, "*")
			filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if strings.HasSuffix(path, ext) {
					f, err := scanner(path)
					if err == nil {
						findings = append(findings, f...)
					}
				}
				return nil
			})
		} else {
			path := filepath.Join(target.URI, pattern)
			if _, err := os.Stat(path); err == nil {
				f, err := scanner(path)
				if err == nil {
					findings = append(findings, f...)
				}
			}
		}
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

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				findings = append(findings, core.Finding{
					RuleID:      "sca-go-dependency",
					Severity:    core.SeverityInfo,
					Category:    "dependency",
					Title:       "Go Dependency Detected",
					Description: "Dependency: " + parts[1],
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
