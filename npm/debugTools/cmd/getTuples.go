package cmd

import (
	"fmt"

	"github.com/Azure/azure-container-networking/npm/debugTools/dataplane"
	"github.com/spf13/cobra"
)

// getTuplesCmd represents the getTuples command
var getTuplesCmd = &cobra.Command{
	Use:   "getTuples",
	Short: "Get a list of hit rule tuples between specified source and destination",
	RunE: func(cmd *cobra.Command, args []string) error {
		src, _ := cmd.Flags().GetString("src")
		if src == "" {
			return fmt.Errorf("no source specified")
		}
		dst, _ := cmd.Flags().GetString("dst")
		if dst == "" {
			return fmt.Errorf("no destination specified")
		}
		npmCacheF, _ := cmd.Flags().GetString("npmF")
		iptableSaveF, _ := cmd.Flags().GetString("iptF")
		srcType := dataplane.GetInputType(src)
		dstType := dataplane.GetInputType(dst)
		srcInput := &dataplane.Input{Content: src, Type: srcType}
		dstInput := &dataplane.Input{Content: dst, Type: dstType}
		if npmCacheF == "" && iptableSaveF == "" {
			_, tuples, err := dataplane.GetNetworkTuple(srcInput, dstInput)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
			for _, tuple := range tuples {
				fmt.Printf("%+v\n", tuple)
			}
		} else {
			_, tuples, err := dataplane.GetNetworkTupleFile(srcInput, dstInput, npmCacheF, iptableSaveF)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
			for _, tuple := range tuples {
				fmt.Printf("%+v\n", tuple)
			}
		}

		return nil
	},
}

func init() {
	debugCmd.AddCommand(getTuplesCmd)
	getTuplesCmd.Flags().StringP("src", "s", "", "set the source")
	getTuplesCmd.Flags().StringP("dst", "d", "", "set the destination")
}
