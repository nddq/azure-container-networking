package dataplane

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/Azure/azure-container-networking/npm/util"
)

func TestParseIptablesObject(t *testing.T) {
	p := &Parser{}
	p.ParseIptablesObjectFile(util.IptablesFilterTable, "../testFiles/iptableSave")
}

func TestParseLine(t *testing.T) {
	type test struct {
		input    string
		expected []byte
	}

	p := &Parser{}

	testL1 := "-A AZURE-NPM -m mark --mark 0x3000 -m comment --comment ACCEPT-on-INGRESS-and-EGRESS-mark-0x3000 -j AZURE-NPM-ACCEPT"                // line with no left or right space
	testL2 := "      -A AZURE-NPM -m mark --mark 0x3000 -m comment --comment ACCEPT-on-INGRESS-and-EGRESS-mark-0x3000 -j AZURE-NPM-ACCEPT"          // line with left space
	testL3 := "-A AZURE-NPM -m mark --mark 0x3000 -m comment --comment ACCEPT-on-INGRESS-and-EGRESS-mark-0x3000 -j AZURE-NPM-ACCEPT       "         // line with right space
	testL4 := "        -A AZURE-NPM -m mark --mark 0x3000 -m comment --comment ACCEPT-on-INGRESS-and-EGRESS-mark-0x3000 -j AZURE-NPM-ACCEPT       " // line with left and right space

	expectByteArray := []byte("-A AZURE-NPM -m mark --mark 0x3000 -m comment --comment ACCEPT-on-INGRESS-and-EGRESS-mark-0x3000 -j AZURE-NPM-ACCEPT")

	tests := []test{
		{input: testL1, expected: expectByteArray},
		{input: testL2, expected: expectByteArray},
		{input: testL3, expected: expectByteArray},
		{input: testL4, expected: expectByteArray},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			actualLine, _ := p.parseLine(0, []byte(tc.input))
			if equal := bytes.Compare(expectByteArray, actualLine); equal != 0 {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualLine)
			}
		})
	}
}

func TestParseRuleFromLine(t *testing.T) {
	type test struct {
		input    string
		expected *IptablesRule
	}
	p := &Parser{}

	m1 := &Module{"set", map[string][]string{"match-set": {"azure-npm-806075013", "dst"}}}
	m2 := &Module{"set", map[string][]string{"match-set": {"azure-npm-3260345197", "src"}}}
	m3 := &Module{"tcp", map[string][]string{"dport": {"8000"}}}
	m4 := &Module{"comment", map[string][]string{"comment": {"ALLOW-allow-ingress-in-ns-test-nwpolicy-0in-AND-TCP-PORT-8000-TO-ns-test-nwpolicy"}}}

	modules := []*Module{m1, m2, m3, m4}

	testR1 := &IptablesRule{"tcp", &Target{"MARK", map[string][]string{"set-xmark": {"0x2000/0xffffffff"}}}, modules}

	tests := []test{
		{input: "-p tcp -d 10.0.153.59/32 -m set --match-set azure-npm-806075013 dst -m set --match-set azure-npm-3260345197 src -m tcp --dport 8000 -m comment --comment ALLOW-allow-ingress-in-ns-test-nwpolicy-0in-AND-TCP-PORT-8000-TO-ns-test-nwpolicy -j MARK --set-xmark 0x2000/0xffffffff", expected: testR1},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			actualRule := p.parseRuleFromLine([]byte(tc.input))
			if !reflect.DeepEqual(tc.expected, actualRule) {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualRule)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	type test struct {
		input    string
		expected *Target
	}
	p := &Parser{}

	testT1 := &Target{"MARK", map[string][]string{"set-xmark": {"0x2000/0xffffffff"}}} // target with option and value
	testT2 := &Target{"RETURN", map[string][]string{}}                                 // target with no option or value

	tests := []test{
		{input: "MARK --set-xmark 0x2000/0xffffffff", expected: testT1},
		{input: "RETURN", expected: testT2},
	}
	for _, tc := range tests {
		actualTarget := &Target{"", make(map[string][]string)}
		t.Run(tc.input, func(t *testing.T) {
			p.parseTarget(0, actualTarget, []byte(tc.input))
			if !reflect.DeepEqual(tc.expected, actualTarget) {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualTarget)
			}
		})
	}
}

func TestParseModule(t *testing.T) {
	type test struct {
		input    string
		expected *Module
	}

	p := &Parser{}

	testM1 := &Module{"set", map[string][]string{"match-set": {"azure-npm-806075013", "dst"}}}                          // single option
	testM2 := &Module{"set", map[string][]string{"not-match-set": {"azure-npm-806075013", "dst"}, "packets-gt": {"0"}}} // multiple options
	testM3 := &Module{"set", map[string][]string{"return-nomatch": {}}}                                                 // option with no values
	tests := []test{
		{input: "set --match-set azure-npm-806075013 dst", expected: testM1},
		{input: "set ! --match-set azure-npm-806075013 dst --packets-gt 0", expected: testM2},
		{input: "set --return-nomatch", expected: testM3},
	}

	for _, tc := range tests {
		actualModule := &Module{"", make(map[string][]string)}
		t.Run(tc.input, func(t *testing.T) {
			p.parseModule(0, actualModule, []byte(tc.input))
			if !reflect.DeepEqual(tc.expected, actualModule) {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualModule)
			}
		})
	}
}
