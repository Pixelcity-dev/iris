package license

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
)

type LicenseScanner struct {
	core.BaseScanner
	name string
}

func NewLicenseScanner() *LicenseScanner {
	return &LicenseScanner{
		BaseScanner: core.BaseScanner{Enabled: true},
		name:        "license",
	}
}

func (s *LicenseScanner) Name() string {
	return s.name
}

func (s *LicenseScanner) Type() core.ScanType {
	return core.ScanTypeLicense
}

func (s *LicenseScanner) SupportedTargets() []core.TargetKind {
	return []core.TargetKind{core.TargetFS, core.TargetRepo}
}

func (s *LicenseScanner) Scan(ctx context.Context, target core.Target, rules []core.Rule) ([]core.Finding, error) {
	var findings []core.Finding

	err := filepath.Walk(target.URI, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.Name() == "LICENSE" || info.Name() == "LICENSE.md" || info.Name() == "LICENSE.txt" || info.Name() == "COPYING" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			content := string(data)
			licenseType := detectLicenseType(content)

			if licenseType != "" {
				relPath, _ := filepath.Rel(target.URI, path)
				findings = append(findings, core.Finding{
					RuleID:      "license-detected",
					Severity:    core.SeverityInfo,
					Category:    "license",
					Title:       "License Detected: " + licenseType,
					Description: "License file found: " + licenseType,
					File:        relPath,
					Confidence:  0.9,
					Metadata: map[string]interface{}{
						"license_type": licenseType,
					},
				})

				if isCopyleftLicense(licenseType) {
					findings = append(findings, core.Finding{
						RuleID:      "license-copyleft",
						Severity:    core.SeverityMedium,
						Category:    "license",
						Title:       "Copyleft License Detected",
						Description: licenseType + " is a copyleft license that requires derivative works to be open source",
						File:        relPath,
						Fix:         "Review license obligations before using in proprietary software",
						References:  []string{"https://choosealicense.com/"},
						Confidence:  0.9,
					})
				}
			}
		}

		return nil
	})

	return findings, err
}

func detectLicenseType(content string) string {
	licenseTypes := map[string][]string{
		"MIT":          {"MIT License", "MIT No Attribution", "MIT-0"},
		"Apache-2.0":   {"Apache License", "Apache-2.0", "Apache 2.0"},
		"GPL-3.0":      {"GNU General Public License v3", "GPL-3.0", "GPLv3"},
		"GPL-2.0":      {"GNU General Public License v2", "GPL-2.0", "GPLv2"},
		"LGPL-3.0":     {"GNU Lesser General Public License v3", "LGPL-3.0", "LGPLv3"},
		"LGPL-2.1":     {"GNU Lesser General Public License v2.1", "LGPL-2.1"},
		"BSD-2-Clause": {"BSD 2-Clause", "Simplified BSD"},
		"BSD-3-Clause": {"BSD 3-Clause", "New BSD", "Modified BSD"},
		"MPL-2.0":      {"Mozilla Public License 2.0", "MPL-2.0"},
		"AGPL-3.0":     {"GNU Affero General Public License v3", "AGPL-3.0", "AGPLv3"},
		"ISC":          {"ISC License"},
		"Unlicense":    {"The Unlicense", "Unlicense"},
		"CC0-1.0":      {"Creative Commons Zero", "CC0"},
	}

	contentLower := strings.ToLower(content)
	for licenseType, keywords := range licenseTypes {
		for _, keyword := range keywords {
			if strings.Contains(contentLower, strings.ToLower(keyword)) {
				return licenseType
			}
		}
	}

	return ""
}

func isCopyleftLicense(licenseType string) bool {
	copyleftLicenses := map[string]bool{
		"GPL-2.0":  true,
		"GPL-3.0":  true,
		"LGPL-2.1": true,
		"LGPL-3.0": true,
		"AGPL-3.0": true,
		"MPL-2.0":  true,
	}
	return copyleftLicenses[licenseType]
}
