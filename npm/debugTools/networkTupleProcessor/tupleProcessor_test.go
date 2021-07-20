package processor

import (
	"testing"
)

func TestGetNetworkTuple(t *testing.T) {
	type srcDstPair struct {
		src *Input
		dst *Input
	}

	// type testInput struct {
	// 	input    *srcDstPair
	// 	expected []*Tuple
	// }
	p := &Processor{}

	i0 := &srcDstPair{src: &Input{Content: "z/b", Type: PODNAME}, dst: &Input{Content: "netpol-4537-x/a", Type: PODNAME}}
	i1 := &srcDstPair{src: &Input{Content: "", Type: INTERNET}, dst: &Input{Content: "testnamespace/a", Type: PODNAME}}
	i2 := &srcDstPair{src: &Input{Content: "testnamespace/a", Type: PODNAME}, dst: &Input{Content: "", Type: INTERNET}}
	i3 := &srcDstPair{src: &Input{Content: "10.240.0.70", Type: IPADDRS}, dst: &Input{Content: "10.240.0.13", Type: IPADDRS}}

	// TODO: CANNOT COMPARE TWO SLICES OF EXPECTED AND ACTUAL RESULT
	// expected0 := []*Tuple{{RuleType: "NOT ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "ANY", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "10.240.0.70", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "10.240.0.70", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"}}

	// expected1 := []*Tuple{{RuleType: "NOT ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "ANY", SrcPort: "ANY", DstIP: "10.240.0.12", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "NOT ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "ANY", SrcPort: "ANY", DstIP: "10.240.0.12", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "ANY", SrcPort: "ANY", DstIP: "10.240.0.12", DstPort: "ANY", Protocol: "ANY"}}

	// expected2 := []*Tuple{{RuleType: "NOT ALLOWED", Direction: pb.Direction_EGRESS, SrcIP: "10.240.0.12", SrcPort: "ANY", DstIP: "ANY", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_EGRESS, SrcIP: "10.240.0.12", SrcPort: "ANY", DstIP: "ANY", DstPort: "53", Protocol: "udp"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_EGRESS, SrcIP: "10.240.0.12", SrcPort: "ANY", DstIP: "ANY", DstPort: "53", Protocol: "tcp"}}

	// expected3 := []*Tuple{{RuleType: "NOT ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "ANY", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "10.240.0.70", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"},
	// 	{RuleType: "ALLOWED", Direction: pb.Direction_INGRESS, SrcIP: "10.240.0.70", SrcPort: "ANY", DstIP: "10.240.0.13", DstPort: "ANY", Protocol: "ANY"}}

	// t0 := &testInput{input: i0, expected: expected0}
	// t1 := &testInput{input: i1, expected: expected1}
	// t2 := &testInput{input: i2, expected: expected2}
	// t3 := &testInput{input: i3, expected: expected3}

	testCases := []*srcDstPair{i0, i1, i2, i3}

	for _, test := range testCases {
		p.GetNetworkTuple(test.src, test.dst, "../testFiles/npmCache.json", "../testFiles/clusterIptableSave")
	}
}
