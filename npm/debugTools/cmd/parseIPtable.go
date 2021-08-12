package cmd

import (
	"fmt"

	"github.com/Azure/azure-container-networking/npm/debugTools/dataplane/parse"

	"github.com/spf13/cobra"
)

// parseIPtableCmd represents the parseIPtable command
var parseIPtableCmd = &cobra.Command{
	Use:   "parseIPtable",
	Short: "Parse iptable into Go object, dumping it to the console",
	RunE: func(cmd *cobra.Command, args []string) error {
		iptableName, _ := cmd.Flags().GetString("table")
		if iptableName == "" {
			iptableName = "filter"
		}
		iptableSaveF, _ := cmd.Flags().GetString("iptF")
		if iptableSaveF == "" {
			iptable, err := parse.Iptables(iptableName)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(iptable.String())
		} else {
			iptable, err := parse.IptablesFile(iptableName, iptableSaveF)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(iptable.String())
		}

		return nil
	},
}

func init() {
	debugCmd.AddCommand(parseIPtableCmd)
}
