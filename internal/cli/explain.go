package cli

import (
	"fmt"

	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/spf13/cobra"
)

var (
	explainRule    bool
	explainFinding bool
)

var explainCmd = &cobra.Command{
	Use:   "explain [rule-id|finding-id]",
	Short: "Explain a security rule or finding",
	Long:  `Get detailed explanation of a security rule or finding, including remediation steps.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runExplain,
}

func init() {
	explainCmd.Flags().BoolVar(&explainRule, "rule", false, "explain a rule")
	explainCmd.Flags().BoolVar(&explainFinding, "finding", false, "explain a finding")
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	id := args[0]

	if rules == nil {
		initRuleEngine()
	}

	rule := rules.GetRuleByID(id)
	if rule != nil {
		printRuleExplanation(rule)
		return nil
	}

	fmt.Printf("No rule or finding found with ID: %s\n", id)
	return nil
}

func printRuleExplanation(rule *core.Rule) {
	fmt.Printf("Rule: %s\n", rule.ID)
	fmt.Printf("Name: %s\n", rule.Name)
	fmt.Printf("Severity: %s\n", rule.Severity)
	fmt.Printf("Category: %s\n", rule.Category)
	fmt.Printf("Language: %s\n", rule.Language)
	fmt.Printf("\nDescription:\n%s\n", rule.Description)
	if rule.Fix != "" {
		fmt.Printf("\nRemediation:\n%s\n", rule.Fix)
	}
	if len(rule.References) > 0 {
		fmt.Printf("\nReferences:\n")
		for _, ref := range rule.References {
			fmt.Printf("  - %s\n", ref)
		}
	}
}
