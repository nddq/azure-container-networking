package converter

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/Azure/azure-container-networking/hack/dataplaneParser/iptable"
)

func TestGetRulesFromIptable(t *testing.T) {
	var (
		iptableBuffer = bytes.NewBuffer(nil)
		tableName     = "filter"
	)

	byteArray, err := ioutil.ReadFile("../testIptable")
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		iptableBuffer.WriteByte(b)
	}

	c := &Converter{}
	c.GetRulesFromIptable(tableName, iptableBuffer)
}

func TestGetRulesFromChain(t *testing.T) {
	iptableChain := &iptable.IptablesChain{}
	iptableChain.Rules = make([]*iptable.IptablesRule, 0)

	m1 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"match-set": {"azure-npm-806075013", "dst"}}}
	m2 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"match-set": {"azure-npm-3260345197", "src"}}}
	m3 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"match-set": {"azure-npm-1468440115", "dst,dst"}}}
	m4 := &iptable.Module{Verb: "tcp", OptionValueMap: map[string][]string{"dport": {"8000"}}}
	m5 := &iptable.Module{Verb: "comment", OptionValueMap: map[string][]string{"comment": {"ALLOW-allow-ingress-in-ns-test-nwpolicy-0in-AND-TCP-PORT-8000-TO-ns-test-nwpolicy"}}}

	modules := []*iptable.Module{m1, m2, m3, m4, m5}

	r1 := &iptable.IptablesRule{Protocol: "tcp",
		Target:  &iptable.Target{Name: "MARK", OptionValueMap: map[string][]string{"set-xmark": {"0x2000/0xffffffff"}}},
		Modules: modules}

	iptableChain.Rules = append(iptableChain.Rules, r1)
	iptableChain.Name = "AZURE-NPM-INGRESS-PORT"

	expectedReponsesArr := []*RuleResponse{{Chain: "AZURE-NPM-INGRESS-PORT",
		SrcList:       []string{"azure-npm-3260345197"},
		DstList:       []string{"azure-npm-806075013", "azure-npm-1468440115"},
		Protocol:      "tcp",
		DPort:         "8000",
		SPort:         "",
		Allowed:       true,
		Direction:     "INGRESS",
		UnsortedIpset: map[string]string{"azure-npm-1468440115": "dst,dst"},
	}}

	c := &Converter{}
	actuatlReponsesArr := c.getRulesFromChain(iptableChain)
	if !reflect.DeepEqual(expectedReponsesArr, actuatlReponsesArr) {
		t.Errorf("expected '%+v', got '%+v'", expectedReponsesArr, actuatlReponsesArr)
	}

}
