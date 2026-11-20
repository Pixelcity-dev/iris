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
	Short: "Scan code, dependencies, containers, and websites",
	Long: `Iris scans source code, dependencies, infrastructure, containers, and websites.
The built-in scanners are compiled in and work offline.

SCANNERS
  sast       pattern rules for risky code (Go, Java, JS/TS, Python, Rust, PHP, Ruby, C/C++, C#, Kotlin, Swift)
  secrets    credentials and private keys; matched values are redacted
  sca        dependency inventory from Go, npm, pip, Maven, Cargo, RubyGems, Composer, NuGet manifests
  iac        Dockerfile, Terraform, and Kubernetes checks
  container  Dockerfile hardening checks
  dast       HTTP security headers, TLS, cookies, and CORS
  webscan    dast plus CSP, exposed files, security.txt, and safe probes
  network    common exposed TCP services
  license    license detection and copyleft flag
  format     whitespace, line endings, indentation, and gofmt
  buildtest  run the project's build and test commands as a gate

EXAMPLES
  iris scan .
  iris scan . --severity high --exit-code
  iris fmt . --check
  iris fmt . --fix
  iris webscan https://example.com --format sarif --output ws.sarif
  iris scan . --format html --output report.html

Docs: https://pixelcity.top/docs/iris`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initConfig(cmd)
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
	rootCmd.SetVersionTemplate(ui.Gold("Iris ", vc) + `{{.Version}} ({{.Name}})
  commit: ` + commit + `
  built:  ` + buildTime + `
  docs:   ` + ui.Gold(`https://pixelcity.top/docs/iris`, vc) + `
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
	rootCmd.PersistentFlags().String("compliance", "", "annotate findings with control mappings: cwe, iso27001, owasp, soc2")
	rootCmd.SetVersionTemplate(`Iris {{.Version}} ({{.Name}})
  commit: ` + commit + `
  built:  ` + buildTime + `
  docs:   https://pixelcity.top/docs/iris
`)
}

// stderrColor reports whether gold accent output may be written to stderr
// for the current command (--no-color, NO_COLOR, dumb TERM, non-TTY).
func stderrColor() bool {
	return ui.ColorOK(rootCmd.PersistentFlags().Changed("no-color"), os.Stderr)
}

// quietEnabled reports whether --quiet was passed (errors only).
func quietEnabled() bool {
	v, err := rootCmd.PersistentFlags().GetBool("quiet")
	return err == nil && v
}

func initConfig(cmd *cobra.Command) {
	loadConfigFile()

	profile, _ := cmd.Flags().GetString("profile")
	if profile != "" {
		if err := config.ApplyProfile(cfg, profile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func loadConfigFile() {
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
	// webscan is always registered so an explicit --scanner webscan works even
	// when the config disables it; the config toggle is honoured when the
	// default scanner set for a URL target is chosen.
	registry.Register(webscan.NewWebScanScanner())
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
