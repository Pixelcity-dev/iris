package cli

import (
	"fmt"
	"os"

	"github.com/Pixelcity-dev/Iris/internal/baseline"
	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/spf13/cobra"
)

var (
	baselineFile     string
	baselineFrom     string
	baselineExitCode bool
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage scan baselines",
	Long:  `Create and compare scan baselines to track new findings.`,
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a baseline from a scan JSON report",
	RunE:  runBaselineCreate,
}

var baselineDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show new findings since a baseline",
	RunE:  runBaselineDiff,
}

func init() {
	baselineCreateCmd.Flags().StringVar(&baselineFrom, "from", "", "scan JSON report to import (required)")
	baselineCreateCmd.Flags().StringVarP(&baselineFile, "output", "o", ".iris-baseline.json", "baseline file path")

	baselineDiffCmd.Flags().StringVar(&baselineFrom, "from", "", "scan JSON report to compare (required)")
	baselineDiffCmd.Flags().StringVarP(&baselineFile, "baseline", "b", ".iris-baseline.json", "baseline file path")
	baselineDiffCmd.Flags().BoolVar(&baselineExitCode, "exit-code", false, "exit non-zero when new findings are present")

	_ = baselineCreateCmd.MarkFlagRequired("from")
	_ = baselineDiffCmd.MarkFlagRequired("from")

	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
	rootCmd.AddCommand(baselineCmd)
}

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	results, err := baseline.LoadResults(baselineFrom)
	if err != nil {
		return fmt.Errorf("load scan results: %w", err)
	}

	b := baseline.FromResults(results)
	if err := baseline.Save(baselineFile, b); err != nil {
		return err
	}

	fmt.Printf("Baseline created: %s (%d findings)\n", baselineFile, len(b.Findings))
	return nil
}

func runBaselineDiff(cmd *cobra.Command, args []string) error {
	b, err := baseline.Load(baselineFile)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}

	results, err := baseline.LoadResults(baselineFrom)
	if err != nil {
		return fmt.Errorf("load scan results: %w", err)
	}

	newResults, suppressed := b.Filter(results)
	newFindings := 0
	for _, r := range newResults {
		newFindings += len(r.Findings)
	}

	if newFindings == 0 {
		fmt.Printf("No new findings since baseline (%d known findings).\n", suppressed)
		return nil
	}

	fmt.Printf("New findings since baseline: %d (%d known findings suppressed)\n\n", newFindings, suppressed)

	rpt := reporter.GetReporter("table")
	output, err := rpt.Generate(newResults, reporter.ReportOptions{
		Format: "table",
		Color:  !rootCmd.PersistentFlags().Changed("no-color"),
	})
	if err != nil {
		return fmt.Errorf("failed to render new findings: %w", err)
	}
	fmt.Print(string(output))

	if baselineExitCode {
		os.Exit(1)
	}
	return nil
}
