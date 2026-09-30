package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/Pixelcity-dev/Iris/internal/scanners/format"
	"github.com/Pixelcity-dev/Iris/internal/ui"
	"github.com/spf13/cobra"
)

var (
	fmtCheck     bool
	fmtFix       bool
	fmtDiff      bool
	fmtOutput    string
	fmtFormat    string
	fmtSeverity  string
	fmtRecursive bool
)

var fmtCmd = &cobra.Command{
	Use:   "fmt [target]",
	Short: "Check and fix code formatting",
	Long: `Check code formatting and optionally fix issues.

Zero-dependency, fast (<50ms), 6 checks:
  - trailing whitespace
  - missing newline at EOF
  - CRLF line endings (Windows)
  - mixed indentation (spaces + tabs)
  - line too long (>120 chars)
  - Go files not gofmt'd (uses stdlib go/format)
  - consecutive blank lines

Examples:
  iris fmt .                 # check current directory
  iris fmt . --check         # check only (exit 1 if issues, CI gate)
  iris fmt . --fix           # auto-fix in place
  iris fmt ./src --fix       # fix specific path
  iris fmt . --diff          # show diff without writing
  iris scan . --scanner format  # as scanner via pipeline`,
	Aliases: []string{"format", "lint:fmt", "style"},
	Args:    cobra.MaximumNArgs(1),
	RunE:    runFmt,
}

func init() {
	fmtCmd.Flags().BoolVar(&fmtCheck, "check", false, "check only, exit 1 if formatting issues found (CI)")
	fmtCmd.Flags().BoolVar(&fmtFix, "fix", false, "fix formatting issues in place (alias --write)")
	fmtCmd.Flags().BoolVar(&fmtFix, "write", false, "alias for --fix")
	fmtCmd.Flags().BoolVar(&fmtDiff, "diff", false, "show diff without modifying files")
	fmtCmd.Flags().StringVarP(&fmtOutput, "output", "o", "", "output file for findings (with --check)")
	fmtCmd.Flags().StringVarP(&fmtFormat, "format", "f", "table", "output format for --check (table, json, sarif, etc.)")
	fmtCmd.Flags().StringVar(&fmtSeverity, "severity", "INFO", "minimum severity for --check (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	fmtCmd.Flags().BoolVarP(&fmtRecursive, "recursive", "r", true, "scan recursively")
	rootCmd.AddCommand(fmtCmd)
}

func runFmt(cmd *cobra.Command, args []string) error {
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	// Default mode: check; if neither --fix nor --diff nor --check explicitly, we still check
	isFix := fmtFix || cmd.Flags().Changed("write")
	isDiff := fmtDiff
	isCheck := fmtCheck || (!isFix && !isDiff)

	// Resolve absolute target for filesystem walk
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	info, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("target not found: %s", target)
	}
	if !info.IsDir() {
		// If single file given, handle directly
		if isFix {
			changed, err := format.FixFile(absTarget)
			if err != nil {
				return fmt.Errorf("failed to fix %s: %w", target, err)
			}
			if changed {
				fmt.Fprintf(os.Stderr, "Fixed %s\n", target)
			} else {
				fmt.Fprintf(os.Stderr, "Already formatted %s\n", target)
			}
			return nil
		}
		// Check single file via scanner
		absTarget = filepath.Dir(absTarget)
		target = absTarget
	}

	if isFix {
		// Auto-fix mode: walk and fix files
		start := time.Now()
		fixedCount := 0
		checkedCount := 0
		err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "dist" || name == "bin" || name == ".next" || name == ".iris" {
					return filepath.SkipDir
				}
				return nil
			}
			// Use same allowlist as scanner
			ext := filepath.Ext(path)
			allow := map[string]bool{".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".py": true, ".rb": true, ".php": true, ".java": true, ".rs": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".kt": true, ".swift": true, ".css": true, ".scss": true, ".html": true, ".vue": true, ".svelte": true, ".json": true, ".yaml": true, ".yml": true, ".toml": true, ".md": true, ".sh": true, ".bash": true, ".zsh": true, ".mjs": true, ".cjs": true, ".sql": true, ".graphql": true}
			base := filepath.Base(path)
			if !allow[ext] && base != "Dockerfile" && base != "Makefile" && base != "Justfile" {
				return nil
			}
			checkedCount++
			changed, err := format.FixFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: fix failed %s: %v\n", path, err)
				return nil
			}
			if changed {
				fixedCount++
				fmt.Fprintf(os.Stderr, "Fixed %s\n", relPath(path, target))
			}
			return nil
		})
		if err != nil {
			return err
		}
		dur := time.Since(start).Seconds()
		fmt.Fprintf(os.Stderr, "\nIris fmt --fix completed in %.2fs\nChecked %d files, fixed %d\n", dur, checkedCount, fixedCount)
		return nil
	}

	if isDiff {
		// Diff mode: show what would change without writing (use scanner to generate findings)
		fmt.Fprintf(os.Stderr, "Iris fmt --diff on %s (showing formatting issues)\n", target)
	}

	// Check mode: use pipeline with format scanner
	fmt.Fprintf(os.Stderr, "Iris fmt --check on %s\n", target)
	ruleEngine := core.NewRuleEngine()
	_ = ruleEngine.LoadRulesFromDir("rules")

	pipeline := core.NewPipeline(registry, ruleEngine)
	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(fmtSeverity)
	pipeline.SetFilter(filter)

	// Live spinner for the format scanner (TTY only).
	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	sp.Start()
	pipeline.SetProgress(sp)

	targetObj := core.Target{Kind: core.TargetFS, URI: target}
	results, err := pipeline.Scan(context.Background(), targetObj, []core.ScanType{core.ScanTypeFormat})
	sp.Stop()
	if err != nil {
		return fmt.Errorf("fmt scan failed: %w", err)
	}
	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}
	dur := 0.0
	for _, r := range results {
		dur += r.Duration
	}
	if isCheck || isDiff {
		fmt.Fprintf(os.Stderr, "Checked in %.2fs • %d formatting issues\n", dur, total)
		if total == 0 {
			fmt.Fprintf(os.Stderr, "Already formatted — no issues\n")
		} else {
			// Generate report via requested format
			rpt := reporter.GetReporter(fmtFormat)
			if rpt == nil {
				return fmt.Errorf("unknown format: %s", fmtFormat)
			}
			output, err := rpt.Generate(results, reporter.ReportOptions{
				Format: fmtFormat,
				Output: fmtOutput,
				Color:  !rootCmd.PersistentFlags().Changed("no-color"),
			})
			if err != nil {
				return err
			}
			if fmtOutput != "" {
				if err := os.WriteFile(fmtOutput, output, 0644); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "Report written to %s\n", fmtOutput)
			} else {
				fmt.Print(string(output))
			}
			fmt.Fprintf(os.Stderr, "\nRun `iris fmt %s --fix` to auto-fix\n", target)
		}
		// For --check in CI, exit 1 if issues found
		if fmtCheck && total > 0 {
			os.Exit(1)
		}
		if isDiff && total > 0 {
			os.Exit(1)
		}
	}
	return nil
}

func relPath(path, base string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}
