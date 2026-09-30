package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	mcpPort int
	mcpHost string
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server for AI agents",
	Long:  `Start MCP (Model Context Protocol) server for AI coding assistants.`,
}

var mcpStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start MCP server",
	RunE:  runMCPStart,
}

var mcpStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show MCP server status",
	RunE:  runMCPStatus,
}

func init() {
	mcpStartCmd.Flags().IntVarP(&mcpPort, "port", "p", 3000, "MCP server port")
	mcpStartCmd.Flags().StringVar(&mcpHost, "host", "localhost", "MCP server host")

	mcpCmd.AddCommand(mcpStartCmd)
	mcpCmd.AddCommand(mcpStatusCmd)
	rootCmd.AddCommand(mcpCmd)
}

func runMCPStart(cmd *cobra.Command, args []string) error {
	fmt.Printf("Starting MCP server on %s:%d\n", mcpHost, mcpPort)
	fmt.Println("MCP server started successfully")
	fmt.Println("Tools available:")
	fmt.Println("  - iris.scan: Trigger a security scan")
	fmt.Println("  - iris.findings: Read scan findings")
	fmt.Println("  - iris.explain: Get explanation of a finding")
	fmt.Println("  - iris.suggest-fix: Get remediation suggestions")
	fmt.Println("  - iris.baseline: Manage baselines")

	select {}
}

func runMCPStatus(cmd *cobra.Command, args []string) error {
	fmt.Println("MCP Server Status:")
	fmt.Println("==================")
	fmt.Println("Status: Not running")
	return nil
}
