package converter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/npm"
	"github.com/Azure/azure-container-networking/npm/debugTools/dataplaneParser/iptable"
	"github.com/Azure/azure-container-networking/npm/debugTools/dataplaneParser/parser"
	"github.com/Azure/azure-container-networking/npm/debugTools/pb"
	"github.com/Azure/azure-container-networking/npm/util"
	"google.golang.org/protobuf/encoding/protojson"
	networkingv1 "k8s.io/api/networking/v1"
)

type Converter struct {
	ListMap           map[string]string
	SetMap            map[string]string
	RequiredChainsMap map[string]bool
	NPMCache          *NPMCache
}

type NPMCache struct {
	Exec             interface{}
	Nodename         string
	NsMap            map[string]*npm.Namespace
	PodMap           map[string]*npm.NpmPod
	RawNpMap         map[string]*networkingv1.NetworkPolicy
	ProcessedNpMap   map[string]*networkingv1.NetworkPolicy
	TelemetryEnabled bool
}

func (c *Converter) GetNpmCache(filename ...string) error {

	c.NPMCache = &NPMCache{}
	if len(filename) > 0 {
		// for dev
		byteArray, err := ioutil.ReadFile(filename[0])
		if err != nil {
			return fmt.Errorf("error occured during reading in file : %w", err)
		}
		err = json.Unmarshal(byteArray, c.NPMCache)
		if err != nil {
			return fmt.Errorf("error occured during unmarshalling : %w", err)
		}
	} else {
		// for deployment
		resp, err := http.Get("http://localhost:10091/npm/v1/debug/manager")
		if err != nil {
			return fmt.Errorf("error occured during curl : %w", err)
		}
		defer resp.Body.Close()
		byteArray, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error occured during reading response's data : %w", err)
		}
		err = json.Unmarshal(byteArray, c.NPMCache)
		if err != nil {
			return fmt.Errorf("error occured during unmarshalling : %w", err)
		}
	}

	return nil
}

// initialize map of chain name that will be include in the result
func (c *Converter) initConverter(npmCacheFile ...string) error {

	c.RequiredChainsMap = make(map[string]bool)
	for _, chain := range RequiredChains {
		c.RequiredChainsMap[chain] = true
	}
	c.ListMap = make(map[string]string)
	c.SetMap = make(map[string]string)
	if len(npmCacheFile) > 0 {
		err := c.GetNpmCache(npmCacheFile[0])
		if err != nil {
			return fmt.Errorf("error occured during initialize converter : %w", err)
		}
	} else {
		err := c.GetNpmCache()
		if err != nil {
			return fmt.Errorf("error occured during initialize converter : %w", err)
		}
	}

	for k := range c.NPMCache.NsMap["all-namespaces"].IpsMgr.ListMap {
		hashedName := util.GetHashedName(k)
		c.ListMap[hashedName] = k
	}
	for k := range c.NPMCache.NsMap["all-namespaces"].IpsMgr.SetMap {
		hashedName := util.GetHashedName(k)
		c.SetMap[hashedName] = k
	}
	return nil

}

// ConvertIptablesObject returns a JSON object of an iptable go oject
// func (c *Converter) ConvertIptablesObject(iptableObj *iptable.Iptables) []byte {
// 	// iptableJson, err := json.Marshal(iptableObj)
// 	iptableJson, err := json.MarshalIndent(iptableObj, "", "    ") // pretty print
// 	if err != nil {
// 		log.Fatalf("Error occured during marshaling. Error: %s", err.Error())
// 	}
// 	return iptableJson
// }

// GetJSONRulesFromIptable returns a list of JSON rule object of an iptable. Can pass in npmCache file and iptable-save files in that order for debugging purposes.
func (c *Converter) GetJSONRulesFromIptable(tableName string, filenames ...string) ([][]byte, error) {
	var pbRuleObj []*pb.RuleResponse
	var err error

	ruleResListJson := make([][]byte, 0)
	m := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
	}
	if len(filenames) > 0 {
		pbRuleObj, err = c.GetProtobufRulesFromIptable(tableName, filenames[0], filenames[1])
		if err != nil {
			return nil, fmt.Errorf("error occured during getting JSON rules from iptables : %w", err)
		}
	} else {
		pbRuleObj, err = c.GetProtobufRulesFromIptable(tableName)
		if err != nil {
			return nil, fmt.Errorf("error occured during getting JSON rules from iptables : %w", err)
		}
	}
	for _, rule := range pbRuleObj {
		ruleJson, err := m.Marshal(rule) // pretty print
		if err != nil {
			return nil, fmt.Errorf("error occured during marshaling : %w", err)
		}
		ruleResListJson = append(ruleResListJson, ruleJson)
	}
	return ruleResListJson, nil

}

// GetRulesFromIptable returns a list of protobuf rule object of an iptable. Can pass in npmCache file and iptable-save files in that order for debugging purposes.
func (c *Converter) GetProtobufRulesFromIptable(tableName string, filenames ...string) ([]*pb.RuleResponse, error) {
	p := &parser.Parser{}
	var ipTableObj *iptable.Iptables

	if len(filenames) > 0 {
		err := c.initConverter(filenames[0])
		if err != nil {
			return nil, fmt.Errorf("error occured during getting protobuf rules from iptables : %w", err)
		}
		ipTableObj = p.ParseIptablesObject(tableName, filenames[1])

	} else {
		err := c.initConverter()
		if err != nil {
			return nil, fmt.Errorf("error occured during getting protobuf rules from iptables : %w", err)
		}
		ipTableObj = p.ParseIptablesObject(tableName)
	}
	ruleResList := make([]*pb.RuleResponse, 0)
	for _, v := range ipTableObj.Chains() {
		chainRules, err := c.getRulesFromChain(v)
		if err != nil {
			return nil, fmt.Errorf("error occured during getting protobuf rules from iptables : %w", err)
		}
		ruleResList = append(ruleResList, chainRules...)
	}

	return ruleResList, nil

}

func (c *Converter) getRulesFromChain(iptableChainObj *iptable.IptablesChain) ([]*pb.RuleResponse, error) {
	rules := make([]*pb.RuleResponse, 0)
	for _, v := range iptableChainObj.Rules() {
		rule := &pb.RuleResponse{}
		rule.Chain = iptableChainObj.Name()
		if _, ok := c.RequiredChainsMap[rule.Chain]; !ok {
			continue
		}
		rule.Protocol = v.Protocol()
		switch v.Target().Name() {
		case "MARK":
			rule.Allowed = true
		case "DROP":
			rule.Allowed = false
		default:
			// ignore other targets
			continue
		}
		direction := c.getRuleDirection(iptableChainObj.Name())
		if direction >= 0 {
			rule.Direction = direction
		}

		err := c.getModulesFromRule(v.Modules(), rule)
		if err != nil {
			return nil, fmt.Errorf("error occured during getting modules from rules : %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (c *Converter) getRuleDirection(iptableChainObjName string) pb.Direction {
	if strings.Contains(iptableChainObjName, "EGRESS") {
		return pb.Direction_EGRESS
	} else if strings.Contains(iptableChainObjName, "INGRESS") {
		return pb.Direction_INGRESS
	} else {
		return -1
	}
}

func (c *Converter) getSetType(name string, m string) pb.SetType {
	if m == "ListMap" { // labels of namespace
		if strings.Contains(name, util.IpsetLabelDelimter) {
			if strings.Count(name, util.IpsetLabelDelimter) > 1 {
				return pb.SetType_NESTEDLABELOFPOD
			}
			return pb.SetType_KEYVALUELABELOFNAMESPACE
		}
		return pb.SetType_KEYLABELOFNAMESPACE
	}
	if strings.HasPrefix(name, util.NamespacePrefix) {
		return pb.SetType_NAMESPACE
	}
	if strings.HasPrefix(name, util.NamedPortIPSetPrefix) {
		return pb.SetType_NAMEDPORTS
	}
	if strings.Contains(name, util.IpsetLabelDelimter) {
		return pb.SetType_KEYVALUELABELOFPOD
	}
	return pb.SetType_KEYLABELOFPOD
}

func (c *Converter) getModulesFromRule(m_list []*iptable.Module, ruleRes *pb.RuleResponse) error {
	ruleRes.SrcList = make([]*pb.RuleResponse_SetInfo, 0)
	ruleRes.DstList = make([]*pb.RuleResponse_SetInfo, 0)
	ruleRes.UnsortedIpset = make(map[string]string)
	for _, m := range m_list {
		switch m.Verb() {
		case "set":
			//set module
			infoObj := &pb.RuleResponse_SetInfo{}
			OptionValueMap := m.OptionValueMap()
			for k, v := range OptionValueMap {
				switch k {
				case "match-set":
					ipsetHashedName := v[0]
					ipsetOrigin := v[1]
					infoObj.HashedSetName = ipsetHashedName
					if v, ok := c.ListMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "ListMap")
					} else if v, ok := c.SetMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "SetMap")
					} else {
						return fmt.Errorf("set %v does not exist", ipsetHashedName)
					}
					infoObj.Included = true

					if len(ipsetOrigin) > 3 {
						ruleRes.UnsortedIpset[ipsetHashedName] = ipsetOrigin
					}
					if strings.Contains(ipsetOrigin, "src") {
						ruleRes.SrcList = append(ruleRes.SrcList, infoObj)
					} else {
						ruleRes.DstList = append(ruleRes.DstList, infoObj)
					}
				case "not-match-set":
					ipsetHashedName := v[0]
					ipsetOrigin := v[1]
					infoObj.HashedSetName = ipsetHashedName
					if v, ok := c.ListMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "ListMap")
					} else if v, ok := c.SetMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "SetMap")
					} else {
						return fmt.Errorf("set %v does not exist", ipsetHashedName)
					}
					infoObj.Included = false

					if len(ipsetOrigin) > 3 {
						ruleRes.UnsortedIpset[ipsetHashedName] = ipsetOrigin
					}
					if strings.Contains(ipsetOrigin, "src") {
						ruleRes.SrcList = append(ruleRes.SrcList, infoObj)
					} else {
						ruleRes.DstList = append(ruleRes.DstList, infoObj)
					}
				default:
					// todo add warning log
					log.Printf("%v option have not been implemented\n", k)
					continue
				}

			}

		case "tcp":
			// tcp module TODO: other protocol
			OptionValueMap := m.OptionValueMap
			for k, v := range OptionValueMap() {
				if k == "dport" {
					portNum, _ := strconv.ParseInt(v[0], 10, 32)
					ruleRes.DPort = int32(portNum)
				} else {
					portNum, _ := strconv.ParseInt(v[0], 10, 32)
					ruleRes.SPort = int32(portNum)
				}
			}
		case "udp":
			OptionValueMap := m.OptionValueMap
			for k, v := range OptionValueMap() {
				if k == "dport" {
					portNum, _ := strconv.ParseInt(v[0], 10, 32)
					ruleRes.DPort = int32(portNum)
				} else {
					portNum, _ := strconv.ParseInt(v[0], 10, 32)
					ruleRes.SPort = int32(portNum)
				}
			}
		default:
			continue
		}
	}
	return nil
}
