package cmd

import (
	"fmt"

	"github.com/Azure/azure-container-networking/npm/debugTools/dataplane"
	"github.com/spf13/cobra"
)

// convertIptableCmd represents the convertIptable command
var convertIPtableCmd = &cobra.Command{
	Use:   "convertIPtable",
	Short: "Get list of iptable's rules in JSON format",
	RunE: func(cmd *cobra.Command, args []string) error {
		iptableName, _ := cmd.Flags().GetString("table")
		if iptableName == "" {
			iptableName = "filter"
		}
		npmCacheF, _ := cmd.Flags().GetString("npmF")
		iptableSaveF, _ := cmd.Flags().GetString("iptF")
		c := &dataplane.Converter{}
		if npmCacheF == "" && iptableSaveF == "" {
			ipTableRulesRes, err := c.GetJSONRulesFromIptables(iptableName)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
			fmt.Printf("%s\n", ipTableRulesRes)
		} else {
			ipTableRulesRes, err := c.GetJSONRulesFromIptableFile(iptableName, npmCacheF, iptableSaveF)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
			fmt.Printf("%s\n", ipTableRulesRes)
		}
		return nil
	},
}

func init() {
	debugCmd.AddCommand(convertIPtableCmd)
}
