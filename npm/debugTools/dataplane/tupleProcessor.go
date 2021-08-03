package dataplane

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/npm"
	"github.com/Azure/azure-container-networking/npm/debugTools/pb"
	"github.com/Azure/azure-container-networking/npm/util"
	"google.golang.org/protobuf/encoding/protojson"
)

type Processor struct{}

type Tuple struct {
	RuleType  string `json:"ruleType"`
	Direction string `json:"direction"`
	SrcIP     string `json:"srcIP"`
	SrcPort   string `json:"srcPort"`
	DstIP     string `json:"dstIP"`
	DstPort   string `json:"dstPort"`
	Protocol  string `json:"protocol"`
}

type Input struct {
	Content string
	Type    InputType
}

type InputType int32

const (
	IPADDRS  InputType = 0
	PODNAME  InputType = 1
	EXTERNAL InputType = 2
)

// GetNetworkTupleFile read from node's NPM cache and iptables-save and returns a list of hit rules between the source and the destination in JSON format and a list of tuples from those rules.
func (p *Processor) GetNetworkTuple(src, dst *Input) ([][]byte, []*Tuple, error) {
	c := &Converter{}

	allRules, err := c.GetProtobufRulesFromIptable("filter")
	if err != nil {
		return nil, nil, fmt.Errorf("error occurred during get network tuple : %w", err)
	}
	return p.getNetworkTupleCommon(src, dst, c.NPMCache, allRules)
}

// GetNetworkTupleFile read from NPM cache and iptables-save files and returns a list of hit rules between the source and the destination in JSON format and a list of tuples from those rules.
func (p *Processor) GetNetworkTupleFile(src, dst *Input, npmCacheFile string, iptableSaveFile string) ([][]byte, []*Tuple, error) {
	c := &Converter{}

	allRules, err := c.GetProtobufRulesFromIptableFile(util.IptablesFilterTable, npmCacheFile, iptableSaveFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error occurred during get network tuple : %w", err)
	}

	return p.getNetworkTupleCommon(src, dst, c.NPMCache, allRules)
}

// Common function
func (p *Processor) getNetworkTupleCommon(src, dst *Input, npmCache *NPMCache, allRules []*pb.RuleResponse) ([][]byte, []*Tuple, error) {
	srcPod, err := p.getCorrespondPod(src, npmCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error occurred during get source pod : %w", err)
	}

	dstPod, err := p.getCorrespondPod(dst, npmCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error occurred during get destination pod : %w", err)
	}

	hitRules, err := p.GetHitRules(srcPod, dstPod, allRules, npmCache)
	if err != nil {
		return nil, nil, fmt.Errorf("error occurred during get hit rules : %w", err)
	}

	if len(hitRules) == 0 {
		// either no hit rules or no rules at all. Both cases allow all traffic
		hitRules = append(hitRules, &pb.RuleResponse{Allowed: true})
	}

	ruleResListJSON := make([][]byte, 0)
	m := protojson.MarshalOptions{
		Indent: "	",
		EmitUnpopulated: true,
	}
	for _, rule := range hitRules {
		ruleJSON, err := m.Marshal(rule) // pretty print
		if err != nil {
			return nil, nil, fmt.Errorf("error occurred during marshalling : %w", err)
		}
		ruleResListJSON = append(ruleResListJSON, ruleJSON)
	}

	resTupleList := make([]*Tuple, 0)
	for _, rule := range hitRules {
		tuple := p.generateTuple(srcPod, dstPod, rule)
		resTupleList = append(resTupleList, tuple)
	}
	// tupleResListJson := make([][]byte, 0)
	// for _, rule := range resTupleList {
	// 	ruleJson, err := json.MarshalIndent(rule, "", "  ")
	// 	if err != nil {
	// 		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	// 	}
	// 	tupleResListJson = append(tupleResListJson, ruleJson)
	// }
	return ruleResListJSON, resTupleList, nil
}

func (p *Processor) getCorrespondPod(origin *Input, cacheObj *NPMCache) (*npm.NpmPod, error) {
	switch origin.Type {
	case PODNAME:
		return cacheObj.PodMap[origin.Content], nil
	case IPADDRS:
		for _, pod := range cacheObj.PodMap {
			if pod.PodIP == origin.Content {
				return pod, nil
			}
		}
		return nil, fmt.Errorf("invalid ipaddress, no equivalent pod found")
	case EXTERNAL:
		return &npm.NpmPod{}, nil
	default:
		return nil, fmt.Errorf("invalid input")
	}
}

// GetInputType returns the type of the input for GetNetworkTuple
func (p *Processor) GetInputType(input string) InputType {
	if input == "External" {
		return EXTERNAL
	} else if _, _, err := net.ParseCIDR(input); err == nil {
		return IPADDRS
	} else {
		return PODNAME
	}
}

func (p *Processor) generateTuple(src, dst *npm.NpmPod, rule *pb.RuleResponse) *Tuple {
	tuple := &Tuple{}
	if rule.Allowed {
		tuple.RuleType = "ALLOWED"
	} else {
		tuple.RuleType = "NOT ALLOWED"
	}
	if rule.Direction == pb.Direction_EGRESS {
		tuple.Direction = "EGRESS"
	} else if rule.Direction == pb.Direction_INGRESS {
		tuple.Direction = "INGRESS"
	} else {
		// not sure if this is correct
		tuple.Direction = ANY
	}
	if len(rule.SrcList) == 0 {
		tuple.SrcIP = ANY
	} else {
		tuple.SrcIP = src.PodIP
	}
	if rule.SPort != 0 {
		tuple.SrcPort = strconv.Itoa(int(rule.SPort))
	} else {
		tuple.SrcPort = ANY
	}
	if len(rule.DstList) == 0 {
		tuple.DstIP = ANY
	} else {
		tuple.DstIP = dst.PodIP
	}
	if rule.DPort != 0 {
		tuple.DstPort = strconv.Itoa(int(rule.DPort))
	} else {
		tuple.DstPort = ANY
	}
	if rule.Protocol != "" {
		tuple.Protocol = rule.Protocol
	} else {
		tuple.Protocol = ANY
	}
	return tuple
}

func (p *Processor) GetHitRules(src, dst *npm.NpmPod, rules []*pb.RuleResponse, cacheObj *NPMCache) ([]*pb.RuleResponse, error) {
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
			matchedSource, err := p.evaluateSetInfo("src", setInfo, src, rule, cacheObj)
			if err != nil {
				return nil, fmt.Errorf("error occurred during evaluating source's set info : %w", err)
			}
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
			matchedDestination, err := p.evaluateSetInfo("dst", setInfo, dst, rule, cacheObj)
			if err != nil {
				return nil, fmt.Errorf("error occurred during evaluating destination's set info : %w", err)
			}
			if !matchedDestination {
				matched = false
				break
			}
		}
		if matched {
			res = append(res, rule)
		}
	}
	return res, nil
}

// evalute an ipset to find out wether the pod's attributes match with the set
func (p *Processor) evaluateSetInfo(origin string, setInfo *pb.RuleResponse_SetInfo, pod *npm.NpmPod, rule *pb.RuleResponse, cacheObj *NPMCache) (bool, error) {
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
		kvList := processNestedLabelOfPod(setInfo.Name)
		hasOneKeyValuePair := false
		for _, kvPair := range kvList {
			key, value := processKeyValueLabelOfPod(kvPair)
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
				if rule.Protocol != "" && rule.Protocol != strings.ToLower(string(namedPort.Protocol)) {
					matched = false
					break
				}
				if rule.Protocol == "" {
					rule.Protocol = strings.ToLower(string(namedPort.Protocol))
				}
				if origin == "src" {
					rule.SPort = namedPort.ContainerPort
				} else {
					rule.DPort = namedPort.ContainerPort
				}
			}
		}
	case pb.SetType_CIDRBLOCKS:
		// TODO
	default:
		return false, fmt.Errorf("invalid set type")
	}

	return matched, nil
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
	kvList := strings.Split(kv, ":")
	key := kvList[0]
	ret := make([]string, 0)
	for _, value := range kvList[1:] {
		ret = append(ret, key+":"+value)
	}
	return ret
}
