package parser

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-container-networking/hack/dataplaneParser/iptable"
)

func TestParseIptablesChainObject(t *testing.T) {

}

func TestParseLine(t *testing.T) {

}

func TestParseChainNameFromRule(t *testing.T) {

}

func TestParseRuleFromLine(t *testing.T) {

}

func TestParseTarget(t *testing.T) {
	type test struct {
		input    string
		expected *iptable.Target
	}
	p := &Parser{}

	testT1 := &iptable.Target{Name: "MARK", OptionValueMap: map[string][]string{"set-xmark": {"0x2000/0xffffffff"}}} // target with option and value
	testT2 := &iptable.Target{Name: "RETURN", OptionValueMap: map[string][]string{}}                                 // target with no option or value

	tests := []test{
		{input: "MARK --set-xmark 0x2000/0xffffffff", expected: testT1},
		{input: "RETURN", expected: testT2},
	}
	for _, tc := range tests {
		actualTarget := &iptable.Target{}
		actualTarget.OptionValueMap = make(map[string][]string)
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
		expected *iptable.Module
	}

	p := &Parser{}

	testM1 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"match-set": {"azure-npm-806075013", "dst"}}}                      // single option
	testM2 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"match-set": {"azure-npm-806075013", "dst"}, "packets-gt": {"0"}}} // multiple options
	testM3 := &iptable.Module{Verb: "set", OptionValueMap: map[string][]string{"return-nomatch": {}}}                                             // option with no values

	tests := []test{
		{input: "set --match-set azure-npm-806075013 dst", expected: testM1},
		{input: "set --match-set azure-npm-806075013 dst --packets-gt 0", expected: testM2},
		{input: "set --return-nomatch", expected: testM3},
	}

	for _, tc := range tests {
		actualModule := &iptable.Module{}
		actualModule.OptionValueMap = make(map[string][]string)
		t.Run(tc.input, func(t *testing.T) {

			p.parseModule(0, actualModule, []byte(tc.input))
			if !reflect.DeepEqual(tc.expected, actualModule) {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualModule)
			}
		})
	}

}
