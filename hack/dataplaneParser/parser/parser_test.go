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

}

func TestParseModule(t *testing.T) {
	type test struct {
		input    string
		expected *iptable.Module
	}

	p := &Parser{}

	testm1 := &iptable.Module{Verb: "set",
		OptionValueMap: map[string][]string{"match-set": {"azure-npm-806075013", "dst"}}}
	testm2 := &iptable.Module{Verb: "set",
		OptionValueMap: map[string][]string{"match-set": {"azure-npm-806075013", "dst"}, "packets-gt": {"0"}}}

	tests := []test{
		{input: "set --match-set azure-npm-806075013 dst ", expected: testm1},
		{input: "set --match-set azure-npm-806075013 dst --packets-gt 0 ", expected: testm2},
	}

	for _, tc := range tests {
		// perform setUp before each test here
		actualModule := &iptable.Module{}
		actualModule.OptionValueMap = make(map[string][]string)
		t.Run(tc.input, func(t *testing.T) {

			p.parseModule(0, actualModule, []byte(tc.input))
			if !reflect.DeepEqual(tc.expected, actualModule) {
				t.Errorf("expected '%+v', got '%+v'", tc.expected, actualModule)
			}
			// perform tearDown after each test here
		})
	}

}

func TestParseOptionAndValue(t *testing.T) {

}
