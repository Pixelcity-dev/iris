package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type GitHubReporter struct{}

func (r *GitHubReporter) Name() string {
	return "github"
}

func (r *GitHubReporter) Extension() string {
	return "json"
}

type GitHubSnapshot struct {
	Schema    string           `json:"$schema"`
	Version   int              `json:"version"`
	Ref       string           `json:"ref"`
	Scanned   string           `json:"scanned"`
	Manifests []GitHubManifest `json:"manifests,omitempty"`
}

type GitHubManifest struct {
	Name    string        `json:"name"`
	File    string        `json:"file"`
	Package GitHubPackage `json:"package"`
}

type GitHubPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (r *GitHubReporter) Generate(results []core.ScanResult, opts ReportOptions) ([]byte, error) {
	output := GitHubSnapshot{
		Schema:  "https://raw.githubusercontent.com/dependencylockfile/dependencylockfile/main/schema.json",
		Version: 1,
		Ref:     "refs/heads/main",
		Scanned: time.Now().UTC().Format(time.RFC3339),
	}

	return json.MarshalIndent(output, "", "  ")
}

func init() {
	_ = fmt.Sprintf
}
