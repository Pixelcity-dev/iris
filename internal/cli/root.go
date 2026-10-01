package cli

import (
	"fmt"
	"os"

	"github.com/Pixelcity-dev/Iris/internal/config"
	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/Pixelcity-dev/Iris/internal/scanners/buildtest"
	"github.com/Pixelcity-dev/Iris/internal/scanners/container"
	"github.com/Pixelcity-dev/Iris/internal/scanners/dast"
	"github.com/Pixelcity-dev/Iris/internal/scanners/format"
	"github.com/Pixelcity-dev/Iris/internal/scanners/iac"
	"github.com/Pixelcity-dev/Iris/internal/scanners/license"
	"github.com/Pixelcity-dev/Iris/internal/scanners/network"
	"github.com/Pixelcity-dev/Iris/internal/scanners/sast"
	"github.com/Pixelcity-dev/Iris/internal/scanners/sca"
	"github.com/Pixelcity-dev/Iris/internal/scanners/secrets"
	"github.com/Pixelcity-dev/Iris/internal/scanners/webscan"
	"github.com/Pixelcity-dev/Iris/internal/ui"
	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	cfg      *config.Config
	registry *core.ScannerRegistry
)

var (
	version   = "1.2.0"
	buildTime = "unknown"
	commit    = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "iris",
	Short: "Iris — Cyber Security Enterprise Tool",
	Long: `Iris — Cyber Security Enterprise Tool

All-in-one security platform. One binary, zero dependencies, covers code + supply chain + cloud + web + formatting.

CAPABILITIES
  Code & Supply Chain  SAST (11+ langs: Go, Java, JS/TS, Python, Rust, PHP, Ruby, C/C++, C#, Kotlin, Swift)
                      SCA (11+ ecosystems: npm, pip, Maven, Go, Cargo, Composer, NuGet, etc.)
                      Secrets (200+ patterns, entropy + verified), License (SPDX/CycloneDX)
  Cloud & Containers   IaC (Terraform, CloudFormation, K8s, Dockerfile), Container (image & Dockerfile), Network
  Web & API            DAST + WebScan (OWASP Top 10, 20+ deep checks: headers, TLS, CORS, CSP, auth, etc.)
  Quality              Format (7 checks: trailing ws, EOF newline, CRLF, mixed indent, long lines, gofmt, blanks) • iris fmt

EXAMPLES
  iris scan .                                      # scan current repo
  iris scan . --severity high --exit-code           # gate on high/critical
  iris fmt . --check                               # formatting gate (CI)
  iris fmt . --fix                                 # auto-fix formatting
  iris webscan https://example.com --format sarif --output ws.sarif
  iris scan https://example.com --scanner webscan,dast --compliance soc2
  iris scan ./app --format html --output report.html

Learn more: https://pixelcity.top/iris  •  Docs: https://pixelcity.top/docs/iris
Support: service@pixelcity.dev  •  MCP: iris mcp start for AI agents`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initConfig()
		initScanners()
	},
}

func Execute() {
	// Brand the version banner with the gold accent; --no-color may appear
	// anywhere on the command line, before cobra has parsed it.
	noColor := false
	for _, a := range os.Args[1:] {
		if a == "--no-color" {
			noColor = true
			break
		}
	}
	vc := ui.ColorOK(noColor, os.Stdout)
	rootCmd.SetVersionTemplate(ui.Gold("Iris ", vc) + `{{.Version}} ({{.Name}}) — Cyber Security Enterprise Tool
  commit: ` + commit + `
  built:  ` + buildTime + `
  scanners: 10  •  langs: 11+  •  ` + ui.Gold(`https://pixelcity.top/docs/iris`, vc) + `
`)

	// cobra's error print is silenced; print once here.
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SilenceErrors = true // Execute() prints the error exactly once
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .iris.yaml, $HOME/.config/iris/config.yaml)")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable ANSI colors (CI)")
	rootCmd.PersistentFlags().Bool("no-upload", false, "never upload results to dashboard scan history")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose diagnostics")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "quiet — errors only")
	rootCmd.PersistentFlags().String("profile", "", "profile (enterprise) — overrides scanners & thresholds")
	rootCmd.PersistentFlags().String("compliance", "", "compliance mapping: soc2, iso27001, gdpr, hipaa, owasp")
	rootCmd.SetVersionTemplate(`Iris {{.Version}} ({{.Name}}) — Cyber Security Enterprise Tool
  commit: ` + commit + `
  built:  ` + buildTime + `
  scanners: 10  •  langs: 11+  •  https://pixelcity.top/docs/iris
`)
}

// stderrColor reports whether gold accent output may be written to stderr
// for the current command (--no-color, NO_COLOR, dumb TERM, non-TTY).
func stderrColor() bool {
	return ui.ColorOK(rootCmd.PersistentFlags().Changed("no-color"), os.Stderr)
}

func initConfig() {
	if cfgFile != "" {
		var err error
		cfg, err = config.LoadConfig(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		cfgFile = config.FindConfigFile()
		if cfgFile != "" {
			var err error
			cfg, err = config.LoadConfig(cfgFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}
		} else {
			cfg = config.DefaultConfig()
		}
	}
}

func initScanners() {
	registry = core.NewScannerRegistry()

	if cfg.Scanners.SAST {
		registry.Register(sast.NewSASTScanner())
	}
	if cfg.Scanners.SCA {
		registry.Register(sca.NewSCAScanner())
	}
	if cfg.Scanners.Secrets {
		registry.Register(secrets.NewSecretsScanner())
	}
	if cfg.Scanners.IAC {
		registry.Register(iac.NewIACScanner())
	}
	if cfg.Scanners.Container {
		registry.Register(container.NewContainerScanner())
	}
	if cfg.Scanners.DAST {
		registry.Register(dast.NewDASTScanner())
	}
	if cfg.Scanners.Network {
		registry.Register(network.NewNetworkScanner())
	}
	if cfg.Scanners.License {
		registry.Register(license.NewLicenseScanner())
	}
	if cfg.Scanners.Format {
		registry.Register(format.NewFormatScanner())
	}
	if cfg.Scanners.WebScan {
		registry.Register(webscan.NewWebScanScanner())
	} else {
		// always register webscan even if disabled in config, so --scanner webscan works
		registry.Register(webscan.NewWebScanScanner())
	}
	// Build tests: analyze project language/structure and run build + tests
	// (registered always; only runs when explicitly requested via --scanner buildtest
	// or enabled in .iris.yaml, since executing builds is opt-in)
	if _, ok := registry.Get(core.ScanTypeBuildTest); !ok {
		registry.Register(buildtest.NewBuildTestScanner())
	}
	// Ensure format is always available for --scanner format even if disabled
	if _, ok := registry.Get(core.ScanTypeFormat); !ok {
		registry.Register(format.NewFormatScanner())
	}
}
