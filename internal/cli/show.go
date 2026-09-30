package cli

import (
	"fmt"
	"os"

	"github.com/Pixelcity-dev/Iris/internal/reporter"
	"github.com/spf13/cobra"
)

var (
	showFormat string
	showPretty bool
)

var showCmd = &cobra.Command{
	Use:   "show [file]",
	Short: "Display scan results",
	Long:  `Pretty-print and display scan results in various formats.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runShow,
}

func init() {
	showCmd.Flags().StringVarP(&showFormat, "format", "f", "table", "output format")
	showCmd.Flags().BoolVarP(&showPretty, "pretty", "p", true, "pretty print JSON")
	rootCmd.AddCommand(showCmd)
}

func runShow(cmd *cobra.Command, args []string) error {
	file := args[0]

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	_ = data

	rpt := reporter.GetReporter(showFormat)
	if rpt == nil {
		return fmt.Errorf("unknown format: %s", showFormat)
	}

	fmt.Printf("Results from: %s\n", file)
	return nil
}
