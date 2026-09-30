package secrets

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type SecretsScanner struct {
	core.BaseScanner
	name     string
	patterns []SecretPattern
}

type SecretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
	Category string
}

func NewSecretsScanner() *SecretsScanner {
	s := &SecretsScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "secrets",
	}
	s.loadPatterns()
	return s
}

func (s *SecretsScanner) loadPatterns() {
	s.patterns = []SecretPattern{
		{Name: "AWS Access Key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: core.SeverityHigh, Category: "cloud-credentials"},
		{Name: "AWS Secret Key", Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}`), Severity: core.SeverityCritical, Category: "cloud-credentials"},
		{Name: "GitHub Token", Pattern: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), Severity: core.SeverityCritical, Category: "api-token"},
		{Name: "GitHub OAuth", Pattern: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), Severity: core.SeverityCritical, Category: "api-token"},
		{Name: "GitLab Token", Pattern: regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20}`), Severity: core.SeverityCritical, Category: "api-token"},
		{Name: "Slack Token", Pattern: regexp.MustCompile(`xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`), Severity: core.SeverityCritical, Category: "api-token"},
		{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}`), Severity: core.SeverityHigh, Category: "webhook"},
		{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Severity: core.SeverityHigh, Category: "api-key"},
		{Name: "Google OAuth", Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Severity: core.SeverityHigh, Category: "oauth"},
		{Name: "Stripe Key", Pattern: regexp.MustCompile(`(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,99}`), Severity: core.SeverityCritical, Category: "api-key"},
		{Name: "Twilio API Key", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Severity: core.SeverityHigh, Category: "api-key"},
		{Name: "SendGrid Key", Pattern: regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}`), Severity: core.SeverityCritical, Category: "api-key"},
		{Name: "Heroku API Key", Pattern: regexp.MustCompile(`(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), Severity: core.SeverityHigh, Category: "api-key"},
		{Name: "Private Key Header", Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Severity: core.SeverityCritical, Category: "private-key"},
		{Name: "JWT Token", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+`), Severity: core.SeverityMedium, Category: "token"},
		{Name: "Password in URL", Pattern: regexp.MustCompile(`(?i)://[^:]+:[^@]+@`), Severity: core.SeverityCritical, Category: "credentials"},
		{Name: "Generic Secret", Pattern: regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['"]([^'"]+)['"]`), Severity: core.SeverityMedium, Category: "credentials"},
		{Name: "Connection String", Pattern: regexp.MustCompile(`(?i)(?:jdbc|mysql|postgres|mongodb|redis)://[^\s'"]+`), Severity: core.SeverityHigh, Category: "database"},
	}
}

func (s *SecretsScanner) Name() string {
	return s.name
}

func (s *SecretsScanner) Type() core.ScanType {
	return core.ScanTypeSecrets
}

func (s *SecretsScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

func (s *SecretsScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	err := filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "node_modules" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		if !isScannable(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		lines := strings.Split(content, "\n")
		relPath, _ := filepath.Rel(target.URI, path)

		fileFindings := s.scanFile(relPath, lines)
		findings = append(findings, fileFindings...)

		return nil
	})

	return findings, err
}

func (s *SecretsScanner) scanFile(path string, lines []string) []core.Finding {
	var findings []core.Finding

	for i, line := range lines {
		for _, pattern := range s.patterns {
			if pattern.Pattern.MatchString(line) {
				finding := core.Finding{
					RuleID:      "secrets-" + strings.ToLower(strings.ReplaceAll(pattern.Name, " ", "-")),
					Severity:    pattern.Severity,
					Category:    pattern.Category,
					Title:       pattern.Name,
					Description: "Potential " + pattern.Name + " detected",
					File:        path,
					Line:        i + 1,
					Code:        redactSecret(strings.TrimSpace(line)),
					Fix:         "Remove the secret from code and use environment variables or a secrets manager",
					Confidence:  0.9,
				}
				finding.GenerateFingerprint()
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func isScannable(path string) bool {
	extensions := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rs": true, ".rb": true, ".php": true, ".cs": true,
		".yaml": true, ".yml": true, ".json": true, ".toml": true, ".env": true,
		".cfg": true, ".conf": true, ".ini": true, ".properties": true,
		".sh": true, ".bash": true, ".zsh": true, ".fish": true,
		".tf": true, ".tfvars": true, ".hcl": true,
		".xml": true, ".sql": true, ".md": true, ".txt": true,
		"Dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
	}

	base := filepath.Base(path)
	ext := filepath.Ext(path)

	if extensions[base] {
		return true
	}
	return extensions[ext]
}

func redactSecret(line string) string {
	if len(line) > 100 {
		return line[:50] + "...[REDACTED]..." + line[len(line)-20:]
	}
	return line
}
