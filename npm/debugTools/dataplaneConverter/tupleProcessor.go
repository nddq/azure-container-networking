package converter

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/Azure/azure-container-networking/hack/pb"
	"github.com/Azure/azure-container-networking/npm"
	"github.com/Azure/azure-container-networking/npm/util"
	"google.golang.org/protobuf/encoding/protojson"
)

type Processor struct {
}

type Tuple struct {
	RuleType  string
	Direction pb.Direction
	SrcIP     string
	SrcPort   string
	DstIP     string
	DstPort   string
	Protocol  string
}

func (p *Processor) GetNetworkTuple(src, dst string) []*Tuple {
	// TODO: Assuming that both src and dst are pod name
	c := &Converter{}

	cacheObj := c.GetNpmCache()
	var (
		srcPod        *npm.NpmPod
		dstPod        *npm.NpmPod
		iptableBuffer = bytes.NewBuffer(nil)
		tableName     = "filter"
	)

	byteArray, err := ioutil.ReadFile("dataplaneConverter/clusterIptableSave")
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		iptableBuffer.WriteByte(b)
	}

	srcPod = cacheObj.PodMap[src]
	dstPod = cacheObj.PodMap[dst]

	allRules := c.GetProtobufRulesFromIptable(tableName, iptableBuffer)
	hitRules := p.GetHitRules(srcPod, dstPod, allRules, cacheObj)

	// for debugging only, will remove
	ruleResListJson := make([][]byte, 0)
	m := protojson.MarshalOptions{
		Indent: "	",
		EmitUnpopulated: true,
	}
	for _, rule := range hitRules {
		ruleJson, err := m.Marshal(rule) // pretty print
		if err != nil {
			log.Fatalf("Error occured during marshaling. Error: %s", err.Error())
		}
		ruleResListJson = append(ruleResListJson, ruleJson)
	}
	fmt.Printf("%s\n", ruleResListJson)
	//

	resTupleList := make([]*Tuple, 0)
	for _, rule := range hitRules {
		tuple := &Tuple{}
		if rule.Allowed {
			tuple.RuleType = "ALLOWED"
		} else {
			tuple.RuleType = "NOT ALLOWED"
		}
		tuple.Direction = rule.Direction
		if len(rule.SrcList) == 0 {
			tuple.SrcIP = "ANY"
		} else {
			tuple.SrcIP = srcPod.PodIP
		}
		if rule.SPort != "" {
			tuple.SrcPort = rule.SPort
		} else {
			tuple.SrcPort = "ANY"
		}
		if len(rule.DstList) == 0 {
			tuple.DstIP = "ANY"
		} else {
			tuple.DstIP = dstPod.PodIP
		}
		if rule.DPort != "" {
			tuple.DstPort = rule.DPort
		} else {
			tuple.DstPort = "ANY"
		}
		if rule.Protocol != "" {
			tuple.Protocol = rule.Protocol
		} else {
			tuple.Protocol = "ANY"
		}
		fmt.Printf("%+v\n", tuple)
		resTupleList = append(resTupleList, tuple)
	}
	return resTupleList

}

func (p *Processor) GetHitRules(src, dst *npm.NpmPod, rules []*pb.RuleResponse, cacheObj *NPMCache) []*pb.RuleResponse {
	res := make([]*pb.RuleResponse, 0)
	for _, rule := range rules {
		matched := true
		for _, setInfo := range rule.SrcList {
			// evalute all match set in src
			switch setInfo.Type {
			case pb.SetType_KEYVALUELABELOFNAMESPACE:
				srcNamespace := util.NamespacePrefix + src.Namespace
				key, expectedValue := processKeyValueLabelOfNameSpace(setInfo.Name)
				actualValue := cacheObj.NsMap[srcNamespace].LabelsMap[key]
				if expectedValue != actualValue || (expectedValue == actualValue && !setInfo.Included) {
					// Either the values does not match or it does match but it was not included
					matched = false
					continue
				}
			case pb.SetType_KEYLABELOFNAMESPACE:
				continue
			case pb.SetType_NAMESPACE:
				srcNamespace := util.NamespacePrefix + src.Namespace
				if setInfo.Name != srcNamespace || (setInfo.Name == srcNamespace && !setInfo.Included) {
					matched = false
					continue
				}
			case pb.SetType_KEYVALUELABELOFPOD:
				key, value := processKeyValueLabelOfPod(setInfo.Name)
				if src.Labels[key] != value || (src.Labels[key] == value && !setInfo.Included) {
					matched = false
					continue
				}
			case pb.SetType_KEYLABELOFPOD:
				continue
			case pb.SetType_NAMEDPORTS:
				continue
			}
		}
		for _, setInfo := range rule.DstList {
			// evaluate all match set in dst
			switch setInfo.Type {
			case pb.SetType_KEYVALUELABELOFNAMESPACE:
				dstNamespace := util.NamespacePrefix + dst.Namespace
				key, expectedValue := processKeyValueLabelOfNameSpace(setInfo.Name)
				actualValue := cacheObj.NsMap[dstNamespace].LabelsMap[key]
				if expectedValue != actualValue || (expectedValue == actualValue && !setInfo.Included) {
					// Either the values does not match or it does match but it was not included
					matched = false
					continue
				}
			case pb.SetType_KEYLABELOFNAMESPACE:
				continue
			case pb.SetType_NAMESPACE:
				dstNamespace := util.NamespacePrefix + dst.Namespace
				if dstNamespace != setInfo.Name || (setInfo.Name == dstNamespace && !setInfo.Included) {
					matched = false
					continue
				}
			case pb.SetType_KEYVALUELABELOFPOD:
				key, value := processKeyValueLabelOfPod(setInfo.Name)
				if dst.Labels[key] != value || (dst.Labels[key] == value && !setInfo.Included) {
					matched = false
					continue
				}
			case pb.SetType_KEYLABELOFPOD:
				continue
			case pb.SetType_NAMEDPORTS:
				continue
			}
		}
		if matched {
			res = append(res, rule)
		}
	}
	return res
}

func processKeyValueLabelOfNameSpace(kv string) (string, string) {
	str := strings.TrimPrefix(kv, util.NamespacePrefix)
	res := strings.Split(str, ":")
	return res[0], res[1]
}

func processKeyValueLabelOfPod(kv string) (string, string) {
	res := strings.Split(kv, ":")
	return res[0], res[1]
}
