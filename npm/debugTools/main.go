package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	converter "github.com/Azure/azure-container-networking/npm/debugTools/dataplaneConverter"
)

func main() {
	var (
		// If required, we can move this buffer one stage up
		// and built as required overtime
		iptableBuffer = bytes.NewBuffer(nil)
		tableName     = "filter"
	)
	// if err := SaveIntoBuffer(tableName, iptableBuffer); err != nil {
	// 	// metrics.SendErrorLogAndMetric(util.IptmID, "[BulkUpdateIPtables] Error: failed to get iptables-save command output with err: %s", err.Error())
	// 	fmt.Println(err.Error())
	// }
	byteArray, err := ioutil.ReadFile("testFiles/clusterIptableSave")
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		iptableBuffer.WriteByte(b)
	}

	// p := &parser.Parser{}
	// iptableObj := p.ParseIptablesObject(tableName, iptableBuffer)
	// iptableObj.PrintIptable()

	c := &converter.Converter{}
	ipTableRulesRes := c.GetJSONRulesFromIptable(tableName, iptableBuffer, "testFiles/npmCache.json")
	fmt.Printf("%s\n", ipTableRulesRes)

	// p := &processor.Processor{}
	// // podname to podname
	// src := &processor.Input{Content: "z/b", Type: processor.PODNAME}
	// dst := &processor.Input{Content: "netpol-4537-x/a", Type: processor.PODNAME}
	// rulesJson, tuple := p.GetNetworkTuple(src, dst)
	// fmt.Printf("%s\n", rulesJson)
	// for _, t := range tuple {
	// 	fmt.Printf("%+v\n", t)
	// }
	// fmt.Println("-------------------")

	// // internet to podname
	// src = &processor.Input{Content: "", Type: processor.INTERNET}
	// dst = &processor.Input{Content: "testnamespace/a", Type: processor.PODNAME}
	// rulesJson, tuple = p.GetNetworkTuple(src, dst)
	// fmt.Printf("%s\n", rulesJson)
	// for _, t := range tuple {
	// 	fmt.Printf("%+v\n", t)
	// }
	// fmt.Println("-------------------")

	// // podname to internet
	// src = &processor.Input{Content: "testnamespace/a", Type: processor.PODNAME}
	// dst = &processor.Input{Content: "", Type: processor.INTERNET}
	// rulesJson, tuple = p.GetNetworkTuple(src, dst)
	// fmt.Printf("%s\n", rulesJson)
	// for _, t := range tuple {
	// 	fmt.Printf("%+v\n", t)
	// }
	// fmt.Println("-------------------")

	// src = &processor.Input{Content: "10.240.0.70", Type: processor.IPADDRS}
	// dst = &processor.Input{Content: "10.240.0.13", Type: processor.IPADDRS}
	// rulesJson, tuple = p.GetNetworkTuple(src, dst, "testFiles/npmCache.json", "testFiles/clusterIptableSave")
	// fmt.Printf("%s\n", rulesJson)
	// for _, t := range tuple {
	// 	fmt.Printf("%+v\n", t)
	// }
	// fmt.Println("-------------------")

}
