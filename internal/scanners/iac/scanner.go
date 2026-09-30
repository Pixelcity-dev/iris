package iac

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type IACScanner struct {
	core.BaseScanner
	name string
}

func NewIACScanner() *IACScanner {
	return &IACScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "iac",
	}
}

func (s *IACScanner) Name() string {
	return s.name
}

func (s *IACScanner) Type() core.ScanType {
	return core.ScanTypeIAC
}

func (s *IACScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

func (s *IACScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	err := filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if !isIACFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		relPath, _ := filepath.Rel(target.URI, path)

		findings = append(findings, scanIACFile(relPath, content)...)

		return nil
	})

	return findings, err
}

func isIACFile(path string) bool {
	base := filepath.Base(path)
	ext := filepath.Ext(path)

	iacFiles := map[string]bool{
		"Dockerfile":          true,
		"docker-compose.yml":  true,
		"docker-compose.yaml": true,
		".dockerignore":       true,
		"Makefile":            true,
		"Vagrantfile":         true,
		"Jenkinsfile":         true,
	}

	iacExtensions := map[string]bool{
		".tf":       true,
		".tfvars":   true,
		".hcl":      true,
		".yaml":     true,
		".yml":      true,
		".json":     true,
		".template": true,
	}

	if iacFiles[base] {
		return true
	}

	if iacExtensions[ext] {
		return true
	}

	return false
}

func scanIACFile(path, content string) []core.Finding {
	var findings []core.Finding

	if isDockerfile(path) {
		findings = append(findings, scanDockerfile(path, content)...)
	}

	if isTerraform(path) {
		findings = append(findings, scanTerraform(path, content)...)
	}

	if isKubernetes(path) {
		findings = append(findings, scanKubernetes(path, content)...)
	}

	return findings
}

func isDockerfile(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(strings.ToLower(base), "dockerfile")
}

func isTerraform(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".tf" || ext == ".tfvars" || ext == ".hcl"
}

func isKubernetes(path string) bool {
	if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	content := string(data)
	return strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:")
}

func scanDockerfile(path, content string) []core.Finding {
	var findings []core.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				image := parts[1]
				if !strings.Contains(image, "@sha256:") && !strings.Contains(image, ":") {
					findings = append(findings, core.Finding{
						RuleID:      "iac-dockerfile-no-version",
						Severity:    core.SeverityMedium,
						Category:    "container",
						Title:       "Docker image without version tag",
						Description: "Image '" + image + "' does not specify a version tag",
						File:        path,
						Line:        i + 1,
						Code:        line,
						Fix:         "Use a specific version tag or digest: " + image + ":latest",
						References:  []string{"https://docs.docker.com/engine/reference/builder/#from"},
						Confidence:  1.0,
					})
				}
			}
		}

		if strings.HasPrefix(strings.ToUpper(line), "RUN ") && strings.Contains(strings.ToLower(line), "apt-get install") && !strings.Contains(line, "-y") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-dockerfile-run-apt-no-yes",
				Severity:    core.SeverityLow,
				Category:    "container",
				Title:       "apt-get install without -y flag",
				Description: "apt-get install without -y may cause build to hang",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Add -y flag: apt-get install -y <package>",
				Confidence:  0.9,
			})
		}

		if strings.HasPrefix(strings.ToUpper(line), "COPY ") || strings.HasPrefix(strings.ToUpper(line), "ADD ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] == "." {
				dir := filepath.Dir(path)
				dockerignore := filepath.Join(dir, ".dockerignore")
				if _, err := os.Stat(dockerignore); err == nil {
					continue
				}
				findings = append(findings, core.Finding{
					RuleID:      "iac-dockerfile-copy-all",
					Severity:    core.SeverityMedium,
					Category:    "container",
					Title:       "COPY/ADD copies entire context",
					Description: "Copying '.' may include unnecessary files like .git, node_modules",
					File:        path,
					Line:        i + 1,
					Code:        line,
					Fix:         "Use .dockerignore to exclude unnecessary files",
					Confidence:  0.8,
				})
			}
		}
	}

	return findings
}

func scanTerraform(path, content string) []core.Finding {
	var findings []core.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "acl = \"public-read\"") || strings.Contains(line, "acl = \"public-read-write\"") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-s3-public-acl",
				Severity:    core.SeverityHigh,
				Category:    "cloud-security",
				Title:       "S3 bucket with public ACL",
				Description: "S3 bucket configured with public access",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Use 'private' ACL or implement bucket policies for fine-grained access control",
				References:  []string{"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-best-practices.html"},
				Confidence:  1.0,
			})
		}

		if strings.Contains(line, "0.0.0.0/0") && !strings.Contains(line, "#") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-open-cidr",
				Severity:    core.SeverityHigh,
				Category:    "network-security",
				Title:       "Security group allows access from 0.0.0.0/0",
				Description: "Security group rule allows access from any IP address",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Restrict CIDR block to specific IP ranges",
				Confidence:  0.9,
			})
		}

		if strings.Contains(strings.ToLower(line), "enable_disabled") || strings.Contains(strings.ToLower(line), "logging = false") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-logging-disabled",
				Severity:    core.SeverityMedium,
				Category:    "compliance",
				Title:       "Logging appears to be disabled",
				Description: "Logging configuration may be disabled",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Enable logging for audit and compliance purposes",
				Confidence:  0.7,
			})
		}
	}

	return findings
}

func scanKubernetes(path, content string) []core.Finding {
	var findings []core.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "privileged: true") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-k8s-privileged-container",
				Severity:    core.SeverityCritical,
				Category:    "container-security",
				Title:       "Privileged container",
				Description: "Container running in privileged mode",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Remove privileged: true and use specific capabilities instead",
				References:  []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
				Confidence:  1.0,
			})
		}

		if strings.Contains(line, "hostNetwork: true") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-k8s-host-network",
				Severity:    core.SeverityHigh,
				Category:    "network-security",
				Title:       "Host network access",
				Description: "Pod uses host network namespace",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Remove hostNetwork: true unless absolutely necessary",
				Confidence:  1.0,
			})
		}

		if strings.Contains(line, "latest") && strings.Contains(content, "image:") {
			findings = append(findings, core.Finding{
				RuleID:      "iac-k8s-image-latest",
				Severity:    core.SeverityMedium,
				Category:    "container-security",
				Title:       "Image with :latest tag",
				Description: "Using :latest tag may lead to unexpected changes",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Use specific image tags or digests",
				Confidence:  0.9,
			})
		}
	}

	return findings
}
