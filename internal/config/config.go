package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version  string        `yaml:"version" json:"version"`
	Scanners ScannerConfig `yaml:"scanners" json:"scanners"`
	Report   ReportConfig  `yaml:"report" json:"report"`
	Rules    RulesConfig   `yaml:"rules" json:"rules"`
	DB       DBConfig      `yaml:"db" json:"db"`
	Plugin   PluginConfig  `yaml:"plugin" json:"plugin"`
	Server   ServerConfig  `yaml:"server" json:"server"`
	Filter   FilterConfig  `yaml:"filter" json:"filter"`
}

type ScannerConfig struct {
	SAST      bool `yaml:"sast" json:"sast"`
	SCA       bool `yaml:"sca" json:"sca"`
	Secrets   bool `yaml:"secrets" json:"secrets"`
	IAC       bool `yaml:"iac" json:"iac"`
	Container bool `yaml:"container" json:"container"`
	DAST      bool `yaml:"dast" json:"dast"`
	Network   bool `yaml:"network" json:"network"`
	License   bool `yaml:"license" json:"license"`
	WebScan   bool `yaml:"webscan" json:"webscan"`
	Format    bool `yaml:"format" json:"format"`
	BuildTest bool `yaml:"buildtest" json:"buildtest"`
}

type ReportConfig struct {
	Format   string `yaml:"format" json:"format"`
	Output   string `yaml:"output" json:"output"`
	Template string `yaml:"template,omitempty" json:"template,omitempty"`
	Color    bool   `yaml:"color" json:"color"`
	Verbose  bool   `yaml:"verbose" json:"verbose"`
}

type RulesConfig struct {
	Paths   []string `yaml:"paths" json:"paths"`
	BuiltIn bool     `yaml:"builtin" json:"builtin"`
	Custom  []string `yaml:"custom,omitempty" json:"custom,omitempty"`
}

type DBConfig struct {
	CacheDir   string `yaml:"cache_dir" json:"cache_dir"`
	UpdateURL  string `yaml:"update_url" json:"update_url"`
	AutoUpdate bool   `yaml:"auto_update" json:"auto_update"`
}

type PluginConfig struct {
	Dir      string          `yaml:"dir" json:"dir"`
	Registry string          `yaml:"registry" json:"registry"`
	Enabled  map[string]bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

type ServerConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
	TLS  bool   `yaml:"tls" json:"tls"`
}

type FilterConfig struct {
	MinSeverity       string   `yaml:"min_severity" json:"min_severity"`
	ExcludeRules      []string `yaml:"exclude_rules,omitempty" json:"exclude_rules,omitempty"`
	IncludeRules      []string `yaml:"include_rules,omitempty" json:"include_rules,omitempty"`
	ExcludeFiles      []string `yaml:"exclude_files,omitempty" json:"exclude_files,omitempty"`
	ExcludeCategories []string `yaml:"exclude_categories,omitempty" json:"exclude_categories,omitempty"`
	Profile           string   `yaml:"profile,omitempty" json:"profile,omitempty"`
	Compliance        []string `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	FailOn            string   `yaml:"fail_on,omitempty" json:"fail_on,omitempty"`
}

type ComplianceMapping struct {
	OWASP    string `yaml:"owasp" json:"owasp"`
	CWE      string `yaml:"cwe" json:"cwe"`
	SOC2     string `yaml:"soc2" json:"soc2"`
	ISO27001 string `yaml:"iso27001" json:"iso27001"`
}

var ComplianceByCategory = map[string]ComplianceMapping{
	"security-headers":       {OWASP: "A05:2021", CWE: "693", SOC2: "CC6.1", ISO27001: "A.14.2.5"},
	"transport-security":     {OWASP: "A01:2021", CWE: "326", SOC2: "CC6.6", ISO27001: "A.10.1.1"},
	"cookie-security":        {OWASP: "A01:2021", CWE: "614", SOC2: "CC6.1", ISO27001: "A.14.1.3"},
	"cors":                   {OWASP: "A01:2021", CWE: "942", SOC2: "CC6.6", ISO27001: "A.13.2.1"},
	"information-disclosure": {OWASP: "A01:2021", CWE: "200", SOC2: "CC6.1", ISO27001: "A.18.1.3"},
	"clickjacking":           {OWASP: "A01:2021", CWE: "1021", SOC2: "CC6.1", ISO27001: "A.14.2.5"},
	"open-redirect":          {OWASP: "A01:2021", CWE: "601", SOC2: "CC6.1", ISO27001: "A.14.2.1"},
	"xss":                    {OWASP: "A03:2021", CWE: "79", SOC2: "CC6.1", ISO27001: "A.14.2.5"},
	"injection":              {OWASP: "A03:2021", CWE: "89", SOC2: "CC6.1", ISO27001: "A.14.2.5"},
	"secrets":                {OWASP: "A07:2021", CWE: "798", SOC2: "CC6.1", ISO27001: "A.9.4.3"},
	"sast":                   {OWASP: "A03:2021", CWE: "20", SOC2: "CC7.2", ISO27001: "A.14.2.1"},
	"sca":                    {OWASP: "A06:2021", CWE: "1104", SOC2: "CC7.2", ISO27001: "A.14.2.7"},
	"style":                  {OWASP: "A04:2021", CWE: "710", SOC2: "CC7.2", ISO27001: "A.14.2.1"},
	"formatting":             {OWASP: "A04:2021", CWE: "710", SOC2: "CC7.2", ISO27001: "A.14.2.1"},
}

func ProfileConfig(profile string) *Config {
	cfg := DefaultConfig()
	switch profile {
	case "startup":
		cfg.Filter.MinSeverity = "LOW"
		cfg.Report.Format = "table"
	case "business":
		cfg.Filter.MinSeverity = "MEDIUM"
		cfg.Filter.Compliance = []string{"soc2", "owasp"}
		cfg.Report.Format = "sarif"
		cfg.Filter.FailOn = "HIGH"
	case "enterprise":
		cfg.Filter.MinSeverity = "LOW"
		cfg.Filter.Compliance = []string{"soc2", "iso27001", "gdpr", "owasp"}
		cfg.Report.Format = "html"
		cfg.Filter.FailOn = "MEDIUM"
		cfg.Scanners.SAST = true
		cfg.Scanners.SCA = true
		cfg.Scanners.Secrets = true
		cfg.Scanners.IAC = true
		cfg.Scanners.Container = true
		cfg.Scanners.DAST = true
		cfg.Scanners.WebScan = true
		cfg.Scanners.Network = true
		cfg.Scanners.License = true
	}
	return cfg
}

func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	cacheDir := filepath.Join(homeDir, ".iris", "cache")
	pluginDir := filepath.Join(homeDir, ".iris", "plugins")

	return &Config{
		Version: "1.2.0",
		Scanners: ScannerConfig{
			SAST:      true,
			SCA:       true,
			Secrets:   true,
			IAC:       true,
			Container: true,
			DAST:      true,
			Network:   true,
			License:   true,
			WebScan:   true,
			Format:    true,
		},
		Report: ReportConfig{
			Format: "table",
			Color:  true,
		},
		Rules: RulesConfig{
			Paths:   []string{},
			BuiltIn: true,
		},
		DB: DBConfig{
			CacheDir:   cacheDir,
			AutoUpdate: true,
		},
		Plugin: PluginConfig{
			Dir:      pluginDir,
			Registry: "https://plugins.iris.dev",
			Enabled:  make(map[string]bool),
		},
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8443,
		},
		Filter: FilterConfig{
			MinSeverity: "INFO",
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func FindConfigFile() string {
	candidates := []string{
		".iris.yaml",
		"iris.yaml",
		".iris.yml",
		"iris.yml",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		homeConfig := filepath.Join(homeDir, ".config", "iris", "config.yaml")
		if _, err := os.Stat(homeConfig); err == nil {
			return homeConfig
		}
	}

	return ""
}

func (c *Config) MergeWith(other *Config) {
	if other.Scanners.SAST {
		c.Scanners.SAST = true
	}
	if other.Scanners.SCA {
		c.Scanners.SCA = true
	}
	if other.Scanners.Secrets {
		c.Scanners.Secrets = true
	}
	if other.Scanners.IAC {
		c.Scanners.IAC = true
	}
	if other.Scanners.Container {
		c.Scanners.Container = true
	}
	if other.Scanners.DAST {
		c.Scanners.DAST = true
	}
	if other.Scanners.Network {
		c.Scanners.Network = true
	}
	if other.Scanners.License {
		c.Scanners.License = true
	}
	if other.Scanners.WebScan {
		c.Scanners.WebScan = true
	}
	if other.Scanners.Format {
		c.Scanners.Format = true
	}
}
