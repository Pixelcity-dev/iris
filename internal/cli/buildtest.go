package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/Pixelcity-dev/Iris/internal/ui"
	"github.com/spf13/cobra"
)

var (
	btSkipBuild bool
	btSkipTests bool
	btFormat    string
	btOutput    string
	btSeverity  string
	btExitCode  bool
)

var buildTestCmd = &cobra.Command{
	Use:     "buildtest [target]",
	Aliases: []string{"build", "bt"},
	Short:   "Automated build & test gate — analyzes project language/structure, then runs builds",
	Long: `Automated build tests.

Analyzes the project's language and structure (manifest detection: go.mod,
package.json, Cargo.toml, pom.xml, build.gradle, pyproject.toml,
requirements.txt — including monorepo subdirectories), then runs the standard
build and test commands for each detected toolchain. Compiler/test errors are
reported as findings with file:line locations and specific fix suggestions.

Examples:
  iris buildtest .                 # build + test
  iris buildtest . --skip-tests    # build only
  iris buildtest . --skip-build    # tests only
  iris buildtest ./dashboard --format json
  iris scan . --scanner buildtest  # as part of a scan`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBuildTest,
}

func init() {
	buildTestCmd.Flags().BoolVar(&btSkipBuild, "skip-build", false, "skip the build step")
	buildTestCmd.Flags().BoolVar(&btSkipTests, "skip-tests", false, "skip the test step")
	buildTestCmd.Flags().StringVarP(&btFormat, "format", "f", "table", "output format (table, json, sarif, html, csv, junit)")
	buildTestCmd.Flags().StringVarP(&btOutput, "output", "o", "", "output file path")
	buildTestCmd.Flags().StringVar(&btSeverity, "severity", "INFO", "minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	buildTestCmd.Flags().BoolVar(&btExitCode, "exit-code", false, "exit 1 if build/test failures found (CI gate)")
	rootCmd.AddCommand(buildTestCmd)
}

func runBuildTest(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	start := time.Now()
	fmt.Fprintf(os.Stderr, "Iris v%s - Automated build tests on %s\n", version, target)

	ruleEngine := core.NewRuleEngine()
	_ = ruleEngine.LoadRulesFromDir("rules")

	pipeline := core.NewPipeline(registry, ruleEngine)
	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(btSeverity)
	pipeline.SetFilter(filter)

	// Configure the buildtest scanner (skip build/tests as requested).
	if s, ok := registry.Get(core.ScanTypeBuildTest); ok {
		if bt, ok := s.(interface {
			SetOptions(skipBuild, skipTests bool)
		}); ok {
			bt.SetOptions(btSkipBuild, btSkipTests)
		}
	}

	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	sp.Start()
	pipeline.SetProgress(sp)

	targetObj := core.Target{Kind: core.TargetFS, URI: target}
	results, err := pipeline.Scan(context.Background(), targetObj, []core.ScanType{core.ScanTypeBuildTest})
	sp.Stop()
	if err != nil {
		return fmt.Errorf("buildtest failed: %w", err)
	}

	for i := range results {
		core.EnrichFixes(results[i].Findings)
	}

	duration := time.Since(start).Seconds()
	total := 0
	failures := 0
	for _, r := range results {
		total += len(r.Findings)
		for _, f := range r.Findings {
			if f.RuleID == "buildtest-build-failed" || f.RuleID == "buildtest-test-failed" ||
				f.RuleID == "buildtest-compile-error" {
				failures++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\nBuild tests completed in %.2f seconds\n", duration)
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "❌ %s\n", pluralize(failures, "build/test failure"))
	} else if total > 0 {
		fmt.Fprintf(os.Stderr, "⚠  %s (no hard failures)\n", pluralize(total, "note"))
	} else {
		fmt.Fprintf(os.Stderr, "✅ All build tests passed\n")
	}

	rpt := reporter.GetReporter(btFormat)
	if rpt == nil {
		return fmt.Errorf("unknown format: %s", btFormat)
	}
	output, err := rpt.Generate(results, reporter.ReportOptions{
		Format: btFormat,
		Output: btOutput,
		Color:  !rootCmd.PersistentFlags().Changed("no-color"),
	})
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if btOutput != "" {
		if err := os.WriteFile(btOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", btOutput)
	} else {
		fmt.Print(string(output))
	}

	if btExitCode && failures > 0 {
		os.Exit(1)
	}
	return nil
}

func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
