package cmd

import (
	"github.com/spf13/cobra"
)

// convertIptableCmd represents the convertIptable command
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Collection of functions related to Azure NPM's debugging tools",
}

func init() {
	rootCmd.AddCommand(debugCmd)
	debugCmd.PersistentFlags().StringP("npmF", "n", "", "Set the NPM cache file path (optional)")
	debugCmd.PersistentFlags().StringP("iptF", "i", "", "Set the iptable-save file path (optional)")
	debugCmd.PersistentFlags().StringP("table", "t", "", "Set table name (default to filter)")
}
