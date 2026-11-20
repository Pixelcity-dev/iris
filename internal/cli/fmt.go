package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

Zero-dependency, fast (<50ms), 7 checks:
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
	fmtCmd.Flags().BoolVar(&fmtDiff, "diff", false, "show a unified diff without modifying files")
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
	isFix := fmtFix || cmd.Flags().Changed("write")
	isDiff := fmtDiff
	isCheck := fmtCheck || (!isFix && !isDiff)

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	info, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("target not found: %s", target)
	}

	singleFile := ""
	if !info.IsDir() {
		singleFile = absTarget
	}

	if isFix {
		if singleFile != "" {
			changed, err := format.FixFile(singleFile)
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
		return fixTree(absTarget)
	}

	if isDiff {
		files := 0
		var err error
		if singleFile != "" {
			changed, derr := printFileDiff(singleFile, filepath.Base(singleFile))
			if derr != nil {
				return derr
			}
			if changed {
				files = 1
			}
		} else {
			files, err = printTreeDiffs(absTarget)
			if err != nil {
				return err
			}
		}
		fmt.Fprintf(os.Stderr, "%d file(s) would be reformatted\n", files)
		if files > 0 {
			os.Exit(1)
		}
		return nil
	}

	if !isCheck {
		return nil
	}

	// Check mode: run the format scanner over the target (or the parent
	// directory of a single file, filtered to that file).
	scanTarget := absTarget
	if singleFile != "" {
		scanTarget = filepath.Dir(absTarget)
	}

	fmt.Fprintf(os.Stderr, "Iris fmt --check on %s\n", target)
	pipeline := core.NewPipeline(registry, loadRuleEngine())
	filter := core.NewFindingFilter()
	filter.MinSeverity = core.ParseSeverity(fmtSeverity)
	pipeline.SetFilter(filter)

	// For a single file the scanner walks its parent directory and results are
	// filtered afterwards, so live progress would report the wrong count.
	sp := ui.NewSpinner(!rootCmd.PersistentFlags().Changed("no-color"))
	if singleFile == "" {
		sp.Start()
		pipeline.SetProgress(sp)
	}

	targetObj := core.Target{Kind: core.TargetFS, URI: scanTarget}
	start := time.Now()
	results, err := pipeline.Scan(context.Background(), targetObj, []core.ScanType{core.ScanTypeFormat})
	sp.Stop()
	if err != nil {
		return fmt.Errorf("fmt scan failed: %w", err)
	}

	if singleFile != "" {
		results = filterResultsToFile(results, filepath.Base(absTarget))
	}

	total := 0
	dur := 0.0
	for _, r := range results {
		total += len(r.Findings)
		dur += r.Duration
	}

	fmt.Fprintf(os.Stderr, "Checked in %.2fs • %d formatting issues\n", dur, total)
	uploadScanBestEffort(context.Background(), "fmt", target, total, dur, results, start)

	if total == 0 {
		fmt.Fprintf(os.Stderr, "Already formatted — no issues\n")
		return nil
	}

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

	if fmtCheck {
		os.Exit(1)
	}
	return nil
}

func fixTree(root string) error {
	start := time.Now()
	fixedCount := 0
	checkedCount := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if core.ShouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !format.IsSupported(path) || info.Size() > core.MaxScanFileBytes {
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
			fmt.Fprintf(os.Stderr, "Fixed %s\n", relPath(path, root))
		}
		return nil
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nIris fmt --fix completed in %.2fs\nChecked %d files, fixed %d\n",
		time.Since(start).Seconds(), checkedCount, fixedCount)
	return nil
}

func printTreeDiffs(root string) (int, error) {
	files := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if core.ShouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !format.IsSupported(path) || info.Size() > core.MaxScanFileBytes {
			return nil
		}
		changed, err := printFileDiff(path, relPath(path, root))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: could not diff %s: %v\n", path, err)
			return nil
		}
		if changed {
			files++
		}
		return nil
	})
	return files, err
}

func printFileDiff(path, displayName string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	original := string(data)
	fixed := format.FixedContent(path, original)
	if fixed == original {
		return false, nil
	}
	fmt.Print(unifiedDiff(displayName, original, fixed))
	return true, nil
}

// unifiedDiff renders a compact unified diff: identical leading and trailing
// lines are omitted and the changed middle is shown as one hunk. Formatting
// fixes are line-local, so this is readable without pulling in a diff library.
func unifiedDiff(name, oldContent, newContent string) string {
	oldLines := strings.Split(strings.TrimSuffix(oldContent, "\n"), "\n")
	newLines := strings.Split(strings.TrimSuffix(newContent, "\n"), "\n")

	start := 0
	for start < len(oldLines) && start < len(newLines) && oldLines[start] == newLines[start] {
		start++
	}
	endOld, endNew := len(oldLines), len(newLines)
	for endOld > start && endNew > start && oldLines[endOld-1] == newLines[endNew-1] {
		endOld--
		endNew--
	}
	if start == endOld && start == endNew {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", name, name)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", start+1, endOld-start, start+1, endNew-start)
	for _, line := range oldLines[start:endOld] {
		b.WriteString("-" + line + "\n")
	}
	for _, line := range newLines[start:endNew] {
		b.WriteString("+" + line + "\n")
	}
	return b.String()
}

func filterResultsToFile(results []core.ScanResult, base string) []core.ScanResult {
	for ri := range results {
		kept := results[ri].Findings[:0]
		for _, f := range results[ri].Findings {
			if filepath.Base(f.File) == base {
				kept = append(kept, f)
			}
		}
		results[ri].Findings = kept
	}
	return results
}

func relPath(path, base string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return rel
}
