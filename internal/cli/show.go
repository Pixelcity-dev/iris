package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/baseline"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/spf13/cobra"
)

var (
	showFormat string
	showOutput string
)

var showCmd = &cobra.Command{
	Use:   "show [file]",
	Short: "Display a saved scan result",
	Long: `Render a scan result written by "iris scan --format json" in any report format.

Examples:
  iris show results.json                 # table view of a saved scan
  iris show results.json --format html -o report.html
  iris show results.json --format sarif  # convert for GitHub Code Scanning`,
	Args: cobra.ExactArgs(1),
	RunE: runShow,
}

func init() {
	showCmd.Flags().StringVarP(&showFormat, "format", "f", "table", "output format (table, json, sarif, cyclonedx, spdx, html, csv, junit)")
	showCmd.Flags().StringVarP(&showOutput, "output", "o", "", "write the report to a file instead of stdout")
	rootCmd.AddCommand(showCmd)
}

func runShow(cmd *cobra.Command, args []string) error {
	file := args[0]

	results, err := baseline.LoadResults(file)
	if err != nil {
		return fmt.Errorf("could not read scan results: %w", err)
	}

	rpt := reporter.GetReporter(showFormat)
	if rpt == nil {
		formats := reporter.ListReporters()
		sort.Strings(formats)
		return fmt.Errorf("unknown format %q (available: %s)", showFormat, strings.Join(formats, ", "))
	}

	output, err := rpt.Generate(results, reporter.ReportOptions{
		Format: showFormat,
		Output: showOutput,
		Color:  !rootCmd.PersistentFlags().Changed("no-color"),
	})
	if err != nil {
		return fmt.Errorf("failed to render report: %w", err)
	}

	if showOutput != "" {
		if err := os.WriteFile(showOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", showOutput)
		return nil
	}

	fmt.Print(string(output))
	return nil
}
