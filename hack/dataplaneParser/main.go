package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/Azure/azure-container-networking/hack/dataplaneParser/iptable"
	"github.com/Azure/azure-container-networking/hack/dataplaneParser/parser"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/npm/util"
)

func SaveIntoBuffer(tableName string, buffer *bytes.Buffer) error {
	l, err := iptable.GrabIptablesLocks()
	if err != nil {
		return err
	}

	defer func(l *os.File) {
		if err = l.Close(); err != nil {
			log.Logf("Failed to close iptables locks")
		}
	}(l)

	cmdArgs := []string{"-t", string(tableName)}
	cmd := exec.Command(util.IptablesSave, cmdArgs...)

	cmd.Stdout = buffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.Stderr = stderrBuffer

	err = cmd.Run()

	if err != nil {
		stderrBuffer.WriteTo(buffer) // ignore error, since we need to return the original error
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
	if err := SaveIntoBuffer(tableName, iptableBuffer); err != nil {
		// metrics.SendErrorLogAndMetric(util.IptmID, "[BulkUpdateIPtables] Error: failed to get iptables-save command output with err: %s", err.Error())
		fmt.Println(err.Error())
	}
	// ruleLineByte := []byte("-p tcp -m set --match-set azure-npm-926814778 src -m set --match-set azure-npm-2107662311 src -m set --match-set azure-npm-2574419033 src -m set --match-set azure-npm-2608925630 dst -m set --match-set azure-npm-2107662311 dst -m set --match-set azure-npm-1797209395 dst -m tcp --dport 80 -m comment --comment 'ALLOW-ns-purpose:development-AND-app:webapp-AND-role:frontend-AND-TCP-PORT-80-TO-app:webapp-AND-role:backend-IN-ns-development' -j MARK --set-xmark 0x2000/0xffffffff")
	// rule := parseRuleFromLine(ruleLineByte)

	// printRule(*rule)
	ipTableObj := parser.CreateIptablesObject(tableName, iptableBuffer.Bytes())

	// printRule(ipTableObj.Chains["AZURE-NPM-INGRESS-PORT"].Rules[0])
	ipTableObj.PrintIptable()

	// -A AZURE-NPM-INGRESS-PORT -p tcp -m set --match-set azure-npm-926814778 src
	// -m set --match-set azure-npm-2107662311 src -m set --match-set azure-npm-2574419033 src
	// -m set --match-set azure-npm-2608925630 dst -m set --match-set azure-npm-2107662311 dst
	// -m set --match-set azure-npm-1797209395 dst -m tcp --dport 80
	// -m comment --comment "ALLOW-ns-purpose:development-AND-app:webapp-AND-role:frontend-AND-TCP-PORT-80-TO-app:webapp-AND-role:backend-IN-ns-development" -j MARK --set-xmark 0x2000/0xffffffff

}
