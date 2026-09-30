package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Pixelcity-dev/Iris/internal/cloud"
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
  - iris cloud upgrade   buy Pro / Enterprise (payments.pixelcity.dev)
  - iris cloud logout    end session

An account is required — create one at https://id.pixelcity.dev (realm: pcid)`,
}

func init() {
	cloudCmd.AddCommand(cloudLoginCmd, cloudLogoutCmd, cloudStatusCmd, cloudUsageCmd, cloudUpgradeCmd)
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
		if len(hist.Entries) == 0 {
			fmt.Println("No scans recorded yet. Run iris scan . to get started.")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TIME\tSCANNER\tTARGET\tFINDINGS\tDURATION")
		for _, e := range hist.Entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%.2fs\n",
				e.Time.Format("2006-01-02 15:04"), e.Scanner, truncateStr(e.Target, 40), e.Findings, e.DurationS)
		}
		return tw.Flush()
	},
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
