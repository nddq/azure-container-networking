package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	processor "github.com/Azure/azure-container-networking/npm/debugTools/networkTupleProcessor"
)

func SaveIntoBuffer(tableName string, buffer *bytes.Buffer) error {
	// l, err := iptm.GrabIptablesLocks()
	// if err != nil {
	// 	return err
	// }

	// defer func(l *os.File) {
	// 	if err = l.Close(); err != nil {
	// 		log.Logf("Failed to close iptables locks")
	// 	}
	// }(l)

	// cmdArgs := []string{"-t", string(tableName)}
	// cmd := exec.Command(util.IptablesSave, cmdArgs...)

	// cmd.Stdout = buffer
	// stderrBuffer := bytes.NewBuffer(nil)
	// cmd.Stderr = stderrBuffer

	// err = cmd.Run()

	// if err != nil {
	// 	stderrBuffer.WriteTo(buffer) // ignore error, since we need to return the original error
	// }
	byteArray, err := ioutil.ReadFile("dataplaneConverter/clusterIptableSave")
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		buffer.WriteByte(b)
	}
	return err
}

func main() {
	// var (
	// 	// If required, we can move this buffer one stage up
	// 	// and built as required overtime
	// 	iptableBuffer = bytes.NewBuffer(nil)
	// 	tableName     = "filter"
	// )
	// // if err := SaveIntoBuffer(tableName, iptableBuffer); err != nil {
	// // 	// metrics.SendErrorLogAndMetric(util.IptmID, "[BulkUpdateIPtables] Error: failed to get iptables-save command output with err: %s", err.Error())
	// // 	fmt.Println(err.Error())
	// // }
	// byteArray, err := ioutil.ReadFile("testFiles/clusterIptableSave")
	// if err != nil {
	// 	fmt.Print(err)
	// }
	// for _, b := range byteArray {
	// 	iptableBuffer.WriteByte(b)
	// }

	// p := &parser.Parser{}
	// iptableObj := p.ParseIptablesObject(tableName, iptableBuffer)
	// iptableObj.PrintIptable()

	// c := &converter.Converter{}
	// ipTableRulesRes := c.GetJSONRulesFromIptable(tableName, iptableBuffer, "testFiles/npmCache.json")
	// fmt.Printf("%s\n", ipTableRulesRes)

	p := &processor.Processor{}
	// podname to podname
	src := &processor.Input{Content: "z/b", Type: processor.PODNAME}
	dst := &processor.Input{Content: "netpol-4537-x/a", Type: processor.PODNAME}
	_, tuple := p.GetNetworkTuple(src, dst)
	fmt.Printf("%s\n", tuple)

	// internet to podname
	src = &processor.Input{Content: "", Type: processor.INTERNET}
	dst = &processor.Input{Content: "testnamespace/a", Type: processor.PODNAME}
	_, tuple = p.GetNetworkTuple(src, dst)
	fmt.Printf("%s\n", tuple)

	// podname to internet
	src = &processor.Input{Content: "testnamespace/a", Type: processor.PODNAME}
	dst = &processor.Input{Content: "", Type: processor.INTERNET}
	_, tuple = p.GetNetworkTuple(src, dst)
	fmt.Printf("%s\n", tuple)

	src = &processor.Input{Content: "10.240.0.70", Type: processor.IPADDRS}
	dst = &processor.Input{Content: "10.240.0.13", Type: processor.IPADDRS}
	_, tuple = p.GetNetworkTuple(src, dst)
	fmt.Printf("%s\n", tuple)

}
