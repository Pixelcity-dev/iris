package cli

import (
	"fmt"
	"os"

	"github.com/Pixelcity-dev/Iris/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Iris configuration",
	Long:  `Create a default .iris.yaml configuration file in the current directory.`,
	RunE:  runInit,
}

func init() {
	initCmd.Flags().Bool("force", false, "overwrite existing config file")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	cfg := config.DefaultConfig()

	force, _ := cmd.Flags().GetBool("force")
	if !force {
		if _, err := os.Stat(".iris.yaml"); err == nil {
			return fmt.Errorf("config file already exists. Use --force to overwrite")
		}
	}

	if err := cfg.Save(".iris.yaml"); err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	fmt.Println("Created .iris.yaml")
	return nil
}
