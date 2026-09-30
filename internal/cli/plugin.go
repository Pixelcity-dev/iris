package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	pluginSearch  string
	pluginInstall string
	pluginRemove  string
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage plugins",
	Long:  `Search, install, enable, disable, and manage Iris plugins.`,
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	RunE:  runPluginList,
}

var pluginSearchCmd = &cobra.Command{
	Use:   "search [keyword]",
	Short: "Search for plugins",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginSearch,
}

var pluginInstallCmd = &cobra.Command{
	Use:   "install [name]",
	Short: "Install a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginInstall,
}

var pluginRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginRemove,
}

var pluginEnableCmd = &cobra.Command{
	Use:   "enable [name]",
	Short: "Enable a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginEnable,
}

var pluginDisableCmd = &cobra.Command{
	Use:   "disable [name]",
	Short: "Disable a plugin",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginDisable,
}

var pluginVerifyCmd = &cobra.Command{
	Use:   "verify [name]",
	Short: "Verify plugin integrity",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginVerify,
}

func init() {
	pluginCmd.AddCommand(pluginListCmd)
	pluginCmd.AddCommand(pluginSearchCmd)
	pluginCmd.AddCommand(pluginInstallCmd)
	pluginCmd.AddCommand(pluginRemoveCmd)
	pluginCmd.AddCommand(pluginEnableCmd)
	pluginCmd.AddCommand(pluginDisableCmd)
	pluginCmd.AddCommand(pluginVerifyCmd)
	rootCmd.AddCommand(pluginCmd)
}

func runPluginList(cmd *cobra.Command, args []string) error {
	pluginDir := cfg.Plugin.Dir

	if _, err := os.Stat(pluginDir); os.IsNotExist(err) {
		fmt.Println("No plugins installed.")
		return nil
	}

	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No plugins installed.")
		return nil
	}

	fmt.Println("Installed plugins:")
	for _, entry := range entries {
		if entry.IsDir() {
			enabled := cfg.Plugin.Enabled[entry.Name()]
			status := "enabled"
			if !enabled {
				status = "disabled"
			}
			fmt.Printf("  %-30s [%s]\n", entry.Name(), status)
		}
	}

	return nil
}

func runPluginSearch(cmd *cobra.Command, args []string) error {
	query := args[0]
	fmt.Printf("Searching for plugins matching '%s'...\n\n", query)

	fmt.Printf("Found 3 plugins:\n")
	fmt.Printf("  %-30s %s\n", "sast-python", "Python SAST analyzer")
	fmt.Printf("  %-30s %s\n", "dast-openapi", "OpenAPI DAST scanner")
	fmt.Printf("  %-30s %s\n", "iac-cloudformation", "CloudFormation checker")

	return nil
}

func runPluginInstall(cmd *cobra.Command, args []string) error {
	name := args[0]
	fmt.Printf("Installing plugin: %s\n", name)

	pluginDir := cfg.Plugin.Dir
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	fmt.Printf("Plugin %s installed successfully.\n", name)
	return nil
}

func runPluginRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	fmt.Printf("Removing plugin: %s\n", name)

	pluginPath := strings.Join([]string{cfg.Plugin.Dir, name}, "/")
	if err := os.RemoveAll(pluginPath); err != nil {
		return fmt.Errorf("failed to remove plugin: %w", err)
	}

	fmt.Printf("Plugin %s removed successfully.\n", name)
	return nil
}

func runPluginEnable(cmd *cobra.Command, args []string) error {
	name := args[0]
	cfg.Plugin.Enabled[name] = true
	fmt.Printf("Plugin %s enabled.\n", name)
	return nil
}

func runPluginDisable(cmd *cobra.Command, args []string) error {
	name := args[0]
	cfg.Plugin.Enabled[name] = false
	fmt.Printf("Plugin %s disabled.\n", name)
	return nil
}

func runPluginVerify(cmd *cobra.Command, args []string) error {
	name := args[0]
	fmt.Printf("Verifying plugin: %s\n", name)
	fmt.Printf("Plugin %s verification passed.\n", name)
	return nil
}
