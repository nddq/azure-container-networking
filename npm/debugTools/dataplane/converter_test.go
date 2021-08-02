package dataplane

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-container-networking/npm/debugTools/pb"
	"github.com/google/go-cmp/cmp"
)

func TestGetJSONRulesFromIptable(t *testing.T) {
	tableName := "filter"

	c := &Converter{}
	_, err := c.GetJSONRulesFromIptableFile(tableName, "../testFiles/npmCache.json", "../testFiles/iptableSave")
	if err != nil {
		t.Errorf("error during TestGetJSONRulesFromIptable : %w", err)
	}
}

func TestGetProtobufRulesFromIptable(t *testing.T) {
	tableName := "filter"

	c := &Converter{}
	_, err := c.GetProtobufRulesFromIptableFile(tableName, "../testFiles/npmCache.json", "../testFiles/iptableSave")
	if err != nil {
		t.Errorf("error during TestGetJSONRulesFromIptable : %w", err)
	}
}

func TestGetSetType(t *testing.T) {
	tests := map[string]struct {
		inputSetName string
		inputMapName string
		expected     pb.SetType
	}{
		"namespace":                    {inputSetName: "ns-testnamespace", inputMapName: "SetMap", expected: pb.SetType_NAMESPACE},
		"key value label of pod":       {inputSetName: "app:frontend", inputMapName: "SetMap", expected: pb.SetType_KEYVALUELABELOFPOD},
		"nested label of pod":          {inputSetName: "k1:v0:v1", inputMapName: "ListMap", expected: pb.SetType_NESTEDLABELOFPOD},
		"key label of namespace":       {inputSetName: "all-namespaces", inputMapName: "ListMap", expected: pb.SetType_KEYLABELOFNAMESPACE},
		"namedports":                   {inputSetName: "namedport:serve-80", inputMapName: "SetMap", expected: pb.SetType_NAMEDPORTS},
		"key label of pod":             {inputSetName: "k0", inputMapName: "SetMap", expected: pb.SetType_KEYLABELOFPOD},
		"key value lable of namespace": {inputSetName: "ns-namespace:test0", inputMapName: "ListMap", expected: pb.SetType_KEYVALUELABELOFNAMESPACE},
	}

	c := &Converter{}
	err := c.initConverterFile("../testFiles/npmCache.json")
	if err != nil {
		t.Errorf("error during initilizing converter : %w", err)
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actualType := c.getSetType(test.inputSetName, test.inputMapName)
			diff := cmp.Diff(test.expected, actualType)
			if diff != "" {
				t.Fatalf(diff)
			}
		})
	}
}

func TestGetRulesFromChain(t *testing.T) {
	type test struct {
		input    *IptablesChain
		expected []*pb.RuleResponse
	}

	iptableChainAllowed := NewIptablesChain("", nil, make([]*IptablesRule, 0))
	iptableChainNotAllowed := NewIptablesChain("", nil, make([]*IptablesRule, 0))

	m0 := NewModule("set", map[string][]string{"match-set": {"azure-npm-2173871756", "dst"}})     // ns-testnamespace - NAMESPACE
	m1 := NewModule("set", map[string][]string{"match-set": {"azure-npm-837532042", "dst"}})      // app:frontend - KEYVALUELABELOFPOD
	m2 := NewModule("set", map[string][]string{"match-set": {"azure-npm-370790958", "dst"}})      // k1:v0:v1 - NESTEDLABELOFPOD
	m3 := NewModule("set", map[string][]string{"match-set": {"azure-npm-530439631", "dst"}})      // all-namespaces - KEYLABELOFNAMESPACE
	m4 := NewModule("set", map[string][]string{"match-set": {"azure-npm-3050895063", "dst,dst"}}) // namedport:serve-80 - NAMEDPORTS
	m5 := NewModule("set", map[string][]string{"match-set": {"azure-npm-2537389870", "dst"}})     // k0 - KEYLABELOFPOD
	m6 := NewModule("set", map[string][]string{"match-set": {"azure-npm-1217484542", "dst"}})     // ns-namespace:test0 - KEYVALUELABELOFNAMESPACE

	m7 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-2173871756", "dst"}})      // ns-testnamespace - NAMESPACE
	m8 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-837532042", "dst"}})       // app:frontend - KEYVALUELABELOFPOD
	m9 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-370790958", "dst"}})       // k1:v0:v1 - NESTEDLABELOFPOD
	m10 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-530439631", "dst"}})      // all-namespaces - KEYLABELOFNAMESPACE
	m11 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-3050895063", "dst,dst"}}) // namedport:serve-80 - NAMEDPORTS
	m12 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-2537389870", "dst"}})     // k0 - KEYLABELOFPOD
	m13 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-1217484542", "dst"}})     // ns-namespace:test0 - KEYVALUELABELOFNAMESPACE

	m14 := NewModule("tcp", map[string][]string{"dport": {"8000"}})
	m15 := NewModule("udp", map[string][]string{"sport": {"53"}})

	s0 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMESPACE, Name: "ns-testnamespace", HashedSetName: "azure-npm-2173871756", Included: true}
	s1 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFPOD, Name: "app:frontend", HashedSetName: "azure-npm-837532042", Included: true}
	s2 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NESTEDLABELOFPOD, Name: "k1:v0:v1", HashedSetName: "azure-npm-370790958", Included: true}
	s3 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFNAMESPACE, Name: "all-namespaces", HashedSetName: "azure-npm-530439631", Included: true}
	s4 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMEDPORTS, Name: "namedport:serve-80", HashedSetName: "azure-npm-3050895063", Included: true}
	s5 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFPOD, Name: "k0", HashedSetName: "azure-npm-2537389870", Included: true}
	s6 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFNAMESPACE, Name: "ns-namespace:test0", HashedSetName: "azure-npm-1217484542", Included: true}

	s7 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMESPACE, Name: "ns-testnamespace", HashedSetName: "azure-npm-2173871756"}
	s8 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFPOD, Name: "app:frontend", HashedSetName: "azure-npm-837532042"}
	s9 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NESTEDLABELOFPOD, Name: "k1:v0:v1", HashedSetName: "azure-npm-370790958"}
	s10 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFNAMESPACE, Name: "all-namespaces", HashedSetName: "azure-npm-530439631"}
	s11 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMEDPORTS, Name: "namedport:serve-80", HashedSetName: "azure-npm-3050895063"}
	s12 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFPOD, Name: "k0", HashedSetName: "azure-npm-2537389870"}
	s13 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFNAMESPACE, Name: "ns-namespace:test0", HashedSetName: "azure-npm-1217484542"}

	modules := []*Module{m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15}
	dstList := []*pb.RuleResponse_SetInfo{s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13}

	r1 := NewIptablesRule("tcp", NewTarget("MARK", map[string][]string{"set-xmark": {"0x2000/0xffffffff"}}), modules)
	r2 := NewIptablesRule("", NewTarget("DROP", map[string][]string{}), modules)

	chainRule := iptableChainAllowed.Rules()
	chainRule = append(chainRule, r1)
	iptableChainAllowed.SetRules(chainRule)
	iptableChainAllowed.SetName("AZURE-NPM-INGRESS-PORT")

	chainRule = iptableChainNotAllowed.Rules()
	chainRule = append(chainRule, r2)
	iptableChainNotAllowed.SetRules(chainRule)
	iptableChainNotAllowed.SetName("AZURE-NPM-INGRESS-DROPS")

	expectedMarkRes := []*pb.RuleResponse{{
		Chain:         "AZURE-NPM-INGRESS-PORT",
		SrcList:       []*pb.RuleResponse_SetInfo{},
		DstList:       dstList,
		Protocol:      "tcp",
		DPort:         8000,
		SPort:         53,
		Allowed:       true,
		Direction:     pb.Direction_INGRESS,
		UnsortedIpset: map[string]string{"azure-npm-3050895063": "dst,dst"},
	}}

	expectedDropRes := []*pb.RuleResponse{{
		Chain:         "AZURE-NPM-INGRESS-DROPS",
		SrcList:       []*pb.RuleResponse_SetInfo{},
		DstList:       dstList,
		Protocol:      "",
		DPort:         8000,
		SPort:         53,
		Allowed:       false,
		Direction:     pb.Direction_INGRESS,
		UnsortedIpset: map[string]string{"azure-npm-3050895063": "dst,dst"},
	}}

	testCases := map[string]*test{
		"allowed rule":     {input: iptableChainAllowed, expected: expectedMarkRes},
		"not allowed rule": {input: iptableChainNotAllowed, expected: expectedDropRes},
	}

	c := &Converter{}
	err := c.initConverterFile("../testFiles/npmCache.json")
	if err != nil {
		t.Errorf("error during initilizing converter : %w", err)
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			actuatlReponsesArr, err := c.getRulesFromChain(test.input)
			if err != nil {
				t.Errorf("error during get rules : %w", err)
			}
			if !reflect.DeepEqual(test.expected, actuatlReponsesArr) {
				t.Errorf("expected '%+v', got '%+v'", test.expected, actuatlReponsesArr)
			}
		})
	}
}

func TestGetModulesFromRule(t *testing.T) {
	m0 := NewModule("set", map[string][]string{"match-set": {"azure-npm-2173871756", "dst"}})     // ns-testnamespace - NAMESPACE
	m1 := NewModule("set", map[string][]string{"match-set": {"azure-npm-837532042", "dst"}})      // app:frontend - KEYVALUELABELOFPOD
	m2 := NewModule("set", map[string][]string{"match-set": {"azure-npm-370790958", "dst"}})      // k1:v0:v1 - NESTEDLABELOFPOD
	m3 := NewModule("set", map[string][]string{"match-set": {"azure-npm-530439631", "dst"}})      // all-namespaces - KEYLABELOFNAMESPACE
	m4 := NewModule("set", map[string][]string{"match-set": {"azure-npm-3050895063", "dst,dst"}}) // namedport:serve-80 - NAMEDPORTS
	m5 := NewModule("set", map[string][]string{"match-set": {"azure-npm-2537389870", "dst"}})     // k0 - KEYLABELOFPOD
	m6 := NewModule("set", map[string][]string{"match-set": {"azure-npm-1217484542", "dst"}})     // ns-namespace:test0 - KEYVALUELABELOFNAMESPACE

	m7 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-2173871756", "dst"}})      // ns-testnamespace - NAMESPACE
	m8 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-837532042", "dst"}})       // app:frontend - KEYVALUELABELOFPOD
	m9 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-370790958", "dst"}})       // k1:v0:v1 - NESTEDLABELOFPOD
	m10 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-530439631", "dst"}})      // all-namespaces - KEYLABELOFNAMESPACE
	m11 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-3050895063", "dst,dst"}}) // namedport:serve-80 - NAMEDPORTS
	m12 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-2537389870", "dst"}})     // k0 - KEYLABELOFPOD
	m13 := NewModule("set", map[string][]string{"not-match-set": {"azure-npm-1217484542", "dst"}})     // ns-namespace:test0 - KEYVALUELABELOFNAMESPACE

	m14 := NewModule("tcp", map[string][]string{"dport": {"8000"}})
	m15 := NewModule("udp", map[string][]string{"sport": {"53"}})

	s0 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMESPACE, Name: "ns-testnamespace", HashedSetName: "azure-npm-2173871756", Included: true}
	s1 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFPOD, Name: "app:frontend", HashedSetName: "azure-npm-837532042", Included: true}
	s2 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NESTEDLABELOFPOD, Name: "k1:v0:v1", HashedSetName: "azure-npm-370790958", Included: true}
	s3 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFNAMESPACE, Name: "all-namespaces", HashedSetName: "azure-npm-530439631", Included: true}
	s4 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMEDPORTS, Name: "namedport:serve-80", HashedSetName: "azure-npm-3050895063", Included: true}
	s5 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFPOD, Name: "k0", HashedSetName: "azure-npm-2537389870", Included: true}
	s6 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFNAMESPACE, Name: "ns-namespace:test0", HashedSetName: "azure-npm-1217484542", Included: true}

	s7 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMESPACE, Name: "ns-testnamespace", HashedSetName: "azure-npm-2173871756"}
	s8 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFPOD, Name: "app:frontend", HashedSetName: "azure-npm-837532042"}
	s9 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NESTEDLABELOFPOD, Name: "k1:v0:v1", HashedSetName: "azure-npm-370790958"}
	s10 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFNAMESPACE, Name: "all-namespaces", HashedSetName: "azure-npm-530439631"}
	s11 := &pb.RuleResponse_SetInfo{Type: pb.SetType_NAMEDPORTS, Name: "namedport:serve-80", HashedSetName: "azure-npm-3050895063"}
	s12 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYLABELOFPOD, Name: "k0", HashedSetName: "azure-npm-2537389870"}
	s13 := &pb.RuleResponse_SetInfo{Type: pb.SetType_KEYVALUELABELOFNAMESPACE, Name: "ns-namespace:test0", HashedSetName: "azure-npm-1217484542"}

	modules := []*Module{m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15}
	dstList := []*pb.RuleResponse_SetInfo{s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13}

	expectedRuleResponse := &pb.RuleResponse{
		Chain:         "TEST",
		SrcList:       []*pb.RuleResponse_SetInfo{},
		DstList:       dstList,
		Protocol:      "",
		DPort:         8000,
		SPort:         53,
		Allowed:       true,
		Direction:     pb.Direction_INGRESS,
		UnsortedIpset: map[string]string{"azure-npm-3050895063": "dst,dst"},
	}

	actualRuleResponse := &pb.RuleResponse{
		Chain:     "TEST",
		Protocol:  "",
		Allowed:   true,
		Direction: pb.Direction_INGRESS,
	}

	c := &Converter{}
	err := c.initConverterFile("../testFiles/npmCache.json")
	if err != nil {
		t.Errorf("error during initilizing converter : %w", err)
	}

	err = c.getModulesFromRule(modules, actualRuleResponse)
	if err != nil {
		t.Errorf("error during getModulesFromRule : %w", err)
	}

	if !reflect.DeepEqual(expectedRuleResponse, actualRuleResponse) {
		t.Errorf("expected '%+v', got '%+v'", expectedRuleResponse, actualRuleResponse)
	}
}
