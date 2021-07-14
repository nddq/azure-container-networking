package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	converter "github.com/Azure/azure-container-networking/hack/dataplaneConverter"
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
	byteArray, err := ioutil.ReadFile("dataplaneConverter/clusterIptableSave")
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
	ipTableRulesRes := c.GetRulesFromIptable(tableName, iptableBuffer)
	fmt.Printf("%s\n", ipTableRulesRes)

	// // fmt.Printf("%s\n", c.ConvertIptablesObject(iptableObj))
}
