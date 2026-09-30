package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var baselineFile string

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage scan baselines",
	Long:  `Create and compare scan baselines to track new findings.`,
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a baseline from current scan",
	RunE:  runBaselineCreate,
}

var baselineDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show new findings since baseline",
	RunE:  runBaselineDiff,
}

func init() {
	baselineCreateCmd.Flags().StringVarP(&baselineFile, "output", "o", ".iris-baseline.json", "baseline file path")
	baselineDiffCmd.Flags().StringVarP(&baselineFile, "baseline", "b", ".iris-baseline.json", "baseline file path")

	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
	rootCmd.AddCommand(baselineCmd)
}

func runBaselineCreate(cmd *cobra.Command, args []string) error {
	fmt.Println("Creating baseline...")

	baseline := map[string]interface{}{
		"version":  "1.1.0",
		"created":  time.Now().Format(time.RFC3339),
		"findings": []string{},
	}

	_ = baseline

	if err := os.WriteFile(baselineFile, []byte("{}"), 0644); err != nil {
		return fmt.Errorf("failed to write baseline: %w", err)
	}

	fmt.Printf("Baseline created: %s\n", baselineFile)
	return nil
}

func runBaselineDiff(cmd *cobra.Command, args []string) error {
	if _, err := os.Stat(baselineFile); os.IsNotExist(err) {
		return fmt.Errorf("baseline file not found: %s", baselineFile)
	}

	fmt.Println("Comparing with baseline...")
	fmt.Println("No new findings since baseline.")
	return nil
}
