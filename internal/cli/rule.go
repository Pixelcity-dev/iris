package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/spf13/cobra"
)

var (
	ruleSearchQ  string
	ruleLanguage string
	ruleCategory string
	ruleSeverity string
	ruleEnabled  bool
	rules        *core.RuleEngine
)

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage security rules",
	Long:  `List, search, enable, and disable security rules.`,
}

var ruleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all rules",
	RunE:  runRuleList,
}

var ruleSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search rules by keyword",
	Args:  cobra.ExactArgs(1),
	RunE:  runRuleSearch,
}

var ruleInfoCmd = &cobra.Command{
	Use:   "info [rule-id]",
	Short: "Show detailed information about a rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runRuleInfo,
}

var ruleStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show rule statistics",
	RunE:  runRuleStats,
}

func init() {
	ruleListCmd.Flags().StringVar(&ruleLanguage, "language", "", "filter by language")
	ruleListCmd.Flags().StringVar(&ruleCategory, "category", "", "filter by category")
	ruleListCmd.Flags().StringVar(&ruleSeverity, "severity", "", "filter by severity")
	ruleListCmd.Flags().BoolVar(&ruleEnabled, "enabled", true, "show only enabled rules")

	ruleCmd.AddCommand(ruleListCmd)
	ruleCmd.AddCommand(ruleSearchCmd)
	ruleCmd.AddCommand(ruleInfoCmd)
	ruleCmd.AddCommand(ruleStatsCmd)
	rootCmd.AddCommand(ruleCmd)
}

func initRuleEngine() {
	rules = core.NewRuleEngine()
	rules.LoadRulesFromDir("rules")
	for _, p := range cfg.Rules.Paths {
		rules.LoadRulesFromDir(p)
	}
}

func runRuleList(cmd *cobra.Command, args []string) error {
	if rules == nil {
		initRuleEngine()
	}
	allRules := rules.GetAllRules()

	var filtered []core.Rule
	for _, r := range allRules {
		if ruleLanguage != "" && !strings.EqualFold(r.Language, ruleLanguage) {
			continue
		}
		if ruleCategory != "" && !strings.EqualFold(r.Category, ruleCategory) {
			continue
		}
		if ruleSeverity != "" && !strings.EqualFold(r.Severity.String(), ruleSeverity) {
			continue
		}
		filtered = append(filtered, r)
	}

	fmt.Printf("Found %d rules:\n\n", len(filtered))
	for _, r := range filtered {
		fmt.Printf("%-50s %s\n", r.ID, r.Name)
	}

	return nil
}

func runRuleSearch(cmd *cobra.Command, args []string) error {
	if rules == nil {
		initRuleEngine()
	}
	query := args[0]
	matches := rules.SearchRules(query)

	fmt.Printf("Found %d rules matching '%s':\n\n", len(matches), query)
	for _, r := range matches {
		fmt.Printf("%-50s %s\n", r.ID, r.Name)
	}

	return nil
}

func runRuleInfo(cmd *cobra.Command, args []string) error {
	if rules == nil {
		initRuleEngine()
	}
	ruleID := args[0]
	rule := rules.GetRuleByID(ruleID)
	if rule == nil {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	fmt.Printf("Rule: %s\n", rule.ID)
	fmt.Printf("Name: %s\n", rule.Name)
	fmt.Printf("Severity: %s\n", rule.Severity)
	fmt.Printf("Category: %s\n", rule.Category)
	fmt.Printf("Language: %s\n", rule.Language)
	fmt.Printf("Description: %s\n", rule.Description)
	if rule.Fix != "" {
		fmt.Printf("Fix: %s\n", rule.Fix)
	}
	if len(rule.References) > 0 {
		fmt.Printf("References:\n")
		for _, ref := range rule.References {
			fmt.Printf("  - %s\n", ref)
		}
	}
	if len(rule.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(rule.Tags, ", "))
	}

	return nil
}

func runRuleStats(cmd *cobra.Command, args []string) error {
	if rules == nil {
		initRuleEngine()
	}
	stats := rules.Stats()

	fmt.Println("Rule Statistics:")
	fmt.Println("===============")
	for scanType, count := range stats {
		fmt.Printf("%-15s %d rules\n", scanType, count)
	}

	return nil
}

func init() {
	_ = filepath.Join("", "")
}
