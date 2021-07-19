package processor

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/npm"
	converter "github.com/Azure/azure-container-networking/npm/debugTools/dataplaneConverter"
	"github.com/Azure/azure-container-networking/npm/debugTools/pb"
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

type Input struct {
	Content string
	Type    InputType
}

type InputType int32

const (
	IPADDRS  InputType = 0
	PODNAME  InputType = 1
	INTERNET InputType = 2
)

func (p *Processor) GetNetworkTuple(src, dst *Input) []*Tuple {
	// TODO: Assuming that both src and dst are pod name
	c := &converter.Converter{}

	cacheObj := c.GetNpmCache()
	var (
		srcPod        *npm.NpmPod
		dstPod        *npm.NpmPod
		iptableBuffer = bytes.NewBuffer(nil)
		tableName     = "filter"
	)

	byteArray, err := ioutil.ReadFile("dataplaneConverter/testFiles/clusterIptableSave")
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		iptableBuffer.WriteByte(b)
	}

	switch src.Type {
	case PODNAME:
		srcPod = cacheObj.PodMap[src.Content]
	case IPADDRS:
		for _, pod := range cacheObj.PodMap {
			if pod.PodIP == src.Content {
				srcPod = pod
				break
			}
		}
		if srcPod == nil {
			panic("No equivalent source pod found")
		}
	case INTERNET:
		srcPod = &npm.NpmPod{}
	default:
		panic("Invalid source type")
	}
	switch dst.Type {
	case PODNAME:
		dstPod = cacheObj.PodMap[dst.Content]
	case IPADDRS:
		for _, pod := range cacheObj.PodMap {
			if pod.PodIP == dst.Content {
				dstPod = pod
				break
			}
		}
		if dstPod == nil {
			panic("No equivalent source pod found")
		}
	case INTERNET:
		dstPod = &npm.NpmPod{}
		if dstPod == nil {
			panic("No equivalent source pod found")
		}
	default:
		panic("Invalid destination type")
	}

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
		if rule.SPort != 0 {
			tuple.SrcPort = strconv.Itoa(int(rule.SPort))
		} else {
			tuple.SrcPort = "ANY"
		}
		if len(rule.DstList) == 0 {
			tuple.DstIP = "ANY"
		} else {
			tuple.DstIP = dstPod.PodIP
		}
		if rule.DPort != 0 {
			tuple.DstPort = strconv.Itoa(int(rule.DPort))
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

func (p *Processor) GetHitRules(src, dst *npm.NpmPod, rules []*pb.RuleResponse, cacheObj *converter.NPMCache) []*pb.RuleResponse {
	res := make([]*pb.RuleResponse, 0)
	for _, rule := range rules {
		matched := true
		for _, setInfo := range rule.SrcList {
			// evalute all match set in src
			if src.Namespace == "" {
				// internet
				matched = false
				break
			}
			matchedSource := p.evaluateSetInfo("src", setInfo, src, rule, cacheObj)
			if !matchedSource {
				matched = false
				break
			}
		}
		for _, setInfo := range rule.DstList {
			// evaluate all match set in dst
			if dst.Namespace == "" {
				// internet
				matched = false
				break
			}
			matchedDestination := p.evaluateSetInfo("dst", setInfo, dst, rule, cacheObj)
			if !matchedDestination {
				matched = false
				break
			}
		}
		if matched {
			res = append(res, rule)
		}
	}
	return res
}

// evalute an ipset to find out wether the pod's attributes match with the set
func (p *Processor) evaluateSetInfo(origin string, setInfo *pb.RuleResponse_SetInfo, pod *npm.NpmPod, rule *pb.RuleResponse, cacheObj *converter.NPMCache) bool {
	matched := true
	switch setInfo.Type {
	case pb.SetType_KEYVALUELABELOFNAMESPACE:
		srcNamespace := util.NamespacePrefix + pod.Namespace
		key, expectedValue := processKeyValueLabelOfNameSpace(setInfo.Name)
		actualValue := cacheObj.NsMap[srcNamespace].LabelsMap[key]
		if expectedValue != actualValue {
			// if the value is required but does not match
			if setInfo.Included {
				matched = false
			}
		} else {
			if !setInfo.Included {
				matched = false
			}
		}
	case pb.SetType_NESTEDLABELOFPOD:
		// a function to split the key and the values and then combine the key with each value
		// return list of key value pairs which are keyvaluelabel of pod
		// one match then break
		kv_list := processNestedLabelOfPod(setInfo.Name)
		hasOneKeyValuePair := false
		for _, kv_pair := range kv_list {
			key, value := processKeyValueLabelOfPod(kv_pair)
			if pod.Labels[key] == value {
				if !setInfo.Included {
					matched = false
					break
				}
				hasOneKeyValuePair = true
				break
			}
		}
		if !hasOneKeyValuePair && setInfo.Included {
			matched = false
		}
	case pb.SetType_KEYLABELOFNAMESPACE:
		srcNamespace := util.NamespacePrefix + pod.Namespace
		key := strings.TrimPrefix(setInfo.Name, util.NamespacePrefix)
		if _, ok := cacheObj.NsMap[srcNamespace].LabelsMap[key]; ok {
			// if the key exists
			if !setInfo.Included {
				// negation contidition
				matched = false
			}
		}
		if setInfo.Included {
			// if key does not exist but required in rule
			matched = false
		}
	case pb.SetType_NAMESPACE:
		srcNamespace := util.NamespacePrefix + pod.Namespace
		if setInfo.Name != srcNamespace || (setInfo.Name == srcNamespace && !setInfo.Included) {
			matched = false
		}
	case pb.SetType_KEYVALUELABELOFPOD:
		key, value := processKeyValueLabelOfPod(setInfo.Name)
		if pod.Labels[key] != value || (pod.Labels[key] == value && !setInfo.Included) {
			matched = false
		}
	case pb.SetType_KEYLABELOFPOD:
		key := setInfo.Name
		if _, ok := pod.Labels[key]; ok {
			if !setInfo.Included {
				matched = false
			}
		}
		if setInfo.Included {
			// if key does not exist but required in rule
			matched = false
		}
	case pb.SetType_NAMEDPORTS:
		portname := strings.TrimPrefix(setInfo.Name, util.NamedPortIPSetPrefix)
		for _, namedPort := range pod.ContainerPorts {
			if namedPort.Name == portname {
				if !setInfo.Included {
					matched = false
					break
				}
				if origin == "src" {
					if rule.Protocol != "" && rule.Protocol != strings.ToLower(string(namedPort.Protocol)) {
						matched = false
						break
					}
					if rule.Protocol == "" {
						rule.Protocol = strings.ToLower(string(namedPort.Protocol))
					}
					rule.SPort = namedPort.ContainerPort
				} else {
					if rule.Protocol != "" && rule.Protocol != strings.ToLower(string(namedPort.Protocol)) {
						matched = false
						break
					}
					if rule.Protocol == "" {
						rule.Protocol = strings.ToLower(string(namedPort.Protocol))
					}
					rule.DPort = namedPort.ContainerPort
				}
			}
		}
	}

	return matched

}

func processKeyValueLabelOfNameSpace(kv string) (string, string) {
	str := strings.TrimPrefix(kv, util.NamespacePrefix)
	ret := strings.Split(str, ":")
	return ret[0], ret[1]
}

func processKeyValueLabelOfPod(kv string) (string, string) {
	ret := strings.Split(kv, ":")
	return ret[0], ret[1]
}

func processNestedLabelOfPod(kv string) []string {
	kv_list := strings.Split(kv, ":")
	key := kv_list[0]
	ret := make([]string, 0)
	for _, value := range kv_list[1:] {
		ret = append(ret, key+":"+value)
	}
	return ret
}
