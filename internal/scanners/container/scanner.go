package container

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type ContainerScanner struct {
	core.BaseScanner
	name string
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "container",
	}
}

func (s *ContainerScanner) Name() string {
	return s.name
}

func (s *ContainerScanner) Type() core.ScanType {
	return core.ScanTypeContainer
}

func (s *ContainerScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetImage, core.TargetFS}
}

func (s *ContainerScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	if target.Kind == core.TargetFS {
		dockerfile := target.URI
		if _, err := os.Stat(dockerfile); err == nil {
			data, err := os.ReadFile(dockerfile)
			if err == nil {
				findings = append(findings, scanDockerConfig(dockerfile, string(data))...)
			}
		}

		composeFiles := []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
		for _, cf := range composeFiles {
			path := target.URI + "/" + cf
			if _, err := os.Stat(path); err == nil {
				data, err := os.ReadFile(path)
				if err == nil {
					findings = append(findings, scanComposeConfig(path, string(data))...)
				}
			}
		}
	}

	return findings, nil
}

func scanDockerConfig(path, content string) []core.Finding {
	var findings []core.Finding
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(strings.ToUpper(line), "EXPOSE ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				port := parts[1]
				if port == "22" || port == "22/tcp" {
					findings = append(findings, core.Finding{
						RuleID:      "container-ssh-exposed",
						Severity:    core.SeverityHigh,
						Category:    "container-security",
						Title:       "SSH port exposed",
						Description: "SSH port 22 is exposed in container",
						File:        path,
						Line:        i + 1,
						Code:        line,
						Fix:         "Remove SSH port exposure unless required for debugging",
						Confidence:  1.0,
					})
				}
			}
		}

		if strings.HasPrefix(strings.ToUpper(line), "USER ROOT") || strings.HasPrefix(strings.ToUpper(line), "USER 0") {
			findings = append(findings, core.Finding{
				RuleID:      "container-root-user",
				Severity:    core.SeverityMedium,
				Category:    "container-security",
				Title:       "Container runs as root",
				Description: "Container is configured to run as root user",
				File:        path,
				Line:        i + 1,
				Code:        line,
				Fix:         "Create and use a non-root user",
				Confidence:  1.0,
			})
		}
	}

	return findings
}

func scanComposeConfig(path, content string) []core.Finding {
	var findings []core.Finding

	var compose map[string]interface{}
	if err := json.Unmarshal([]byte(content), &compose); err != nil {
		return findings
	}

	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return findings
	}

	for serviceName, serviceDef := range services {
		service, ok := serviceDef.(map[string]interface{})
		if !ok {
			continue
		}

		if privileged, ok := service["privileged"].(bool); ok && privileged {
			findings = append(findings, core.Finding{
				RuleID:      "container-privileged-service",
				Severity:    core.SeverityCritical,
				Category:    "container-security",
				Title:       "Privileged service: " + serviceName,
				Description: "Service '" + serviceName + "' runs in privileged mode",
				File:        path,
				Fix:         "Remove privileged mode and use specific capabilities",
				Confidence:  1.0,
			})
		}

		if networkMode, ok := service["network_mode"].(string); ok && networkMode == "host" {
			findings = append(findings, core.Finding{
				RuleID:      "container-host-network",
				Severity:    core.SeverityHigh,
				Category:    "container-security",
				Title:       "Host network mode: " + serviceName,
				Description: "Service '" + serviceName + "' uses host network",
				File:        path,
				Fix:         "Use bridge network or create custom network",
				Confidence:  1.0,
			})
		}
	}

	return findings
}
