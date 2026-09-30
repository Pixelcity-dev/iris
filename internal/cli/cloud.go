package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/cloud"
	"github.com/Pixelcity-dev/Iris/internal/core"
	"github.com/spf13/cobra"
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "PixelCity account: login, plan, usage, upgrade",
	Long: `PixelCity cloud account for Iris.

Connects your CLI to your PixelCity ID (id.pixelcity.dev) account:
  - iris cloud login     sign in via browser (device flow)
  - iris cloud status    show account, plan and quota usage
  - iris cloud usage     recent scan history
  - iris cloud show ID   one scan's full findings table
  - iris cloud upgrade   buy Pro / Enterprise (payments.pixelcity.dev)
  - iris cloud logout    end session

An account is required — create one at https://id.pixelcity.dev (realm: pcid)`,
}

func init() {
	cloudCmd.AddCommand(cloudLoginCmd, cloudLogoutCmd, cloudStatusCmd, cloudUsageCmd, cloudShowCmd, cloudUpgradeCmd)
	rootCmd.AddCommand(cloudCmd)
}

var cloudLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in with your PixelCity ID account",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := cloud.DefaultConfig()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		tok, err := cloud.Login(ctx, cfg, os.Stderr)
		if err != nil {
			return err
		}
		claims, err := cloud.Whoami(ctx, cfg, tok.AccessToken)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Logged in (could not fetch profile details)")
			return nil
		}
		fmt.Fprintf(os.Stderr, "✅ Logged in as %s <%s>\n", claims.PreferredUsername, claims.Email)
		fmt.Fprintf(os.Stderr, "Plan & usage: iris cloud status\n")
		return nil
	},
}

var cloudLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Sign out and clear the local session",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cloud.Logout(context.Background(), cloud.DefaultConfig()); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Signed out.")
		return nil
	},
}

var cloudStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show account, plan and quota usage",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := cloud.DefaultConfig()
		ctx := context.Background()
		token, err := cloud.EnsureValidToken(ctx, cfg)
		if err != nil {
			return err
		}
		claims, err := cloud.Whoami(ctx, cfg, token)
		if err != nil {
			return fmt.Errorf("session invalid: %w", err)
		}
		plan, err := cloud.GetPlan(ctx, cfg, token)
		if err != nil {
			return fmt.Errorf("could not fetch plan (is dashboard.pixelcity.dev reachable?): %w", err)
		}

		fmt.Printf("Account:  %s <%s>\n", claims.PreferredUsername, claims.Email)
		fmt.Printf("Plan:     %s (%s)\n", plan.Name, plan.Tier)
		if !plan.ValidUntil.IsZero() {
			fmt.Printf("Renews:   %s\n", plan.ValidUntil.Format("2006-01-02"))
		}
		fmt.Printf("Scans:    %d / %d used\n", plan.ScansUsed, plan.ScanQuota)
		if plan.Tier != "free" {
			fmt.Printf("AI pages: %d / %d used\n", plan.AIPagesUsed, plan.AIPagesQuota)
		}
		if len(plan.Features) > 0 {
			fmt.Printf("Features: %s\n", joinList(plan.Features))
		}
		if plan.Tier == "free" {
			fmt.Printf("\nUpgrade: iris cloud upgrade pro | enterprise\n")
		}
		return nil
	},
}

var (
	usageJSON bool
)

var cloudUsageCmd = &cobra.Command{
	Use:   "usage",
	Short: "Show recent scan history",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := cloud.DefaultConfig()
		ctx := context.Background()
		token, err := cloud.EnsureValidToken(ctx, cfg)
		if err != nil {
			return err
		}
		hist, err := cloud.GetUsage(ctx, cfg, token, 25)
		if err != nil {
			return err
		}
		if usageJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(hist)
		}
		if len(hist.Entries) == 0 {
			fmt.Println("No scans recorded yet. Run iris scan . to get started.")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tSCANNER\tTARGET\tFINDINGS\tDURATION\tID")
		for _, e := range hist.Entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%.2fs\t%s\n",
				e.Time.Format("2006-01-02 15:04"), e.Scanner, truncateStr(e.Target, 28),
				e.Findings, e.DurationS, e.ID)
		}
		return tw.Flush()
	},
}

var (
	showJSON bool
	showFix  bool
)

var cloudShowCmd = &cobra.Command{
	Use:          "show <scan-id>",
	Short:        "Show one stored scan with its full findings",
	SilenceUsage: true,
	Long: `Show one scan from the dashboard history with a full findings table.

Find scan ids with: iris cloud usage
Export raw instead with: --json (or the dashboard Export links).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := strings.TrimSpace(args[0])
		if id == "" {
			return errors.New("scan id required — find ids with: iris cloud usage")
		}
		cfg := cloud.DefaultConfig()
		ctx := context.Background()
		token, err := cloud.EnsureValidToken(ctx, cfg)
		if err != nil {
			return err
		}
		d, err := cloud.GetScan(ctx, cfg, token, id)
		if err != nil {
			return err
		}
		if showJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(d)
		}
		e := d.Entry
		fmt.Printf("Scan %s\n", e.ID)
		fmt.Printf("  Time:     %s\n", e.Time.Local().Format("2006-01-02 15:04:05"))
		fmt.Printf("  Scanner:  %s\n", e.Scanner)
		fmt.Printf("  Target:   %s\n", e.Target)
		if len(e.SeverityCounts) > 0 {
			fmt.Printf("  Severity: %s\n", sevSummary(e.SeverityCounts))
		}
		ver := e.Version
		if ver == "" {
			ver = "-"
		}
		fmt.Printf("  Findings: %d   Duration: %.2fs   Iris: %s\n", e.Findings, e.DurationS, ver)
		if e.ReportOmitted {
			fmt.Println("  Report was omitted (exceeded size cap) — metadata only.")
			return nil
		}
		if len(d.Report) == 0 {
			fmt.Println("  No stored report for this scan (metadata only).")
			return nil
		}
		var rep struct {
			Results []core.ScanResult `json:"results"`
		}
		if err := json.Unmarshal(d.Report, &rep); err != nil {
			return fmt.Errorf("parse stored report: %w", err)
		}
		type row struct {
			sev   core.Severity
			rule  string
			title string
			fix   string
		}
		var rows []row
		for _, r := range rep.Results {
			for _, f := range r.Findings {
				title := f.Title
				if title == "" {
					title = f.Description
				}
				rows = append(rows, row{f.Severity, f.RuleID, title, f.Fix})
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].sev != rows[j].sev {
				return rows[i].sev > rows[j].sev
			}
			return rows[i].rule < rows[j].rule
		})
		if len(rows) == 0 {
			fmt.Println("\nNo findings — clean scan.")
			return nil
		}
		const maxRows = 100
		shown := rows
		if len(shown) > maxRows {
			shown = shown[:maxRows]
		}
		fmt.Println()
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SEV\tRULE\tTITLE")
		for _, r := range shown {
			fmt.Fprintf(tw, "%s\t%s\t%s\n",
				r.sev.String(), truncateStr(r.rule, 28), truncateStr(r.title, 72))
		}
		_ = tw.Flush()
		if showFix {
			for _, r := range shown {
				if strings.TrimSpace(r.fix) == "" {
					continue
				}
				fmt.Printf("\n  %s  %s\n    fix: %s\n", r.sev.String(), r.rule, r.fix)
			}
		}
		if len(rows) > len(shown) {
			fmt.Printf("\nShowing first %d of %d findings — full report via --json or the dashboard export.\n",
				len(shown), len(rows))
		}
		return nil
	},
}

func init() {
	cloudShowCmd.Flags().BoolVar(&showJSON, "json", false, "print the raw scan record + report as JSON")
	cloudShowCmd.Flags().BoolVar(&showFix, "fix", false, "print remediation guidance for each finding")
}

// sevSummary renders severity counts as "high=4 medium=3 ..." (stable order).
func sevSummary(counts map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, k := range order {
		if v := counts[k]; v > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	for k, v := range counts {
		if v > 0 && !containsStr(order, k) {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	return strings.Join(parts, " ")
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

var (
	upPlan     string
	upInterval string
)

var cloudUpgradeCmd = &cobra.Command{
	Use:   "upgrade [pro|enterprise]",
	Short: "Buy Pro or Enterprise via payments.pixelcity.dev",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		plan := args[0]
		if plan != "pro" && plan != "enterprise" {
			return fmt.Errorf("unknown plan %q — use 'pro' or 'enterprise'", plan)
		}
		cfg := cloud.DefaultConfig()
		ctx := context.Background()
		token, err := cloud.EnsureValidToken(ctx, cfg)
		if err != nil {
			return err
		}
		cs, err := cloud.CreateCheckout(ctx, cfg, token, plan, upInterval)
		if err != nil {
			return err
		}
		fmt.Printf("%s (%s) — %s / %s\n", plan, cs.SessionID, formatCents(cs.AmountCents, cs.Currency), upInterval)
		fmt.Printf("\nComplete the purchase in your browser:\n  %s\n", cs.URL)
		fmt.Printf("\nAfter payment, run: iris cloud status  (plan activates automatically)\n")
		return nil
	},
}

func init() {
	cloudUpgradeCmd.Flags().StringVar(&upInterval, "interval", "monthly", "billing interval: monthly | yearly")
	cloudUsageCmd.Flags().BoolVar(&usageJSON, "json", false, "print the raw usage history as JSON")
}

func joinList(items []string) string {
	out := ""
	for i, it := range items {
		if i > 0 {
			out += ", "
		}
		out += it
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func formatCents(c int64, currency string) string {
	return fmt.Sprintf("%.2f %s", float64(c)/100, currency)
}
