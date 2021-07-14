package converter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/Azure/azure-container-networking/npm"
	"github.com/Azure/azure-container-networking/npm/debugTools/dataplaneParser/iptable"
	"github.com/Azure/azure-container-networking/npm/debugTools/dataplaneParser/parser"
	"github.com/Azure/azure-container-networking/npm/debugTools/pb"
	"github.com/Azure/azure-container-networking/npm/util"
	"google.golang.org/protobuf/encoding/protojson"
	networkingv1 "k8s.io/api/networking/v1"
	utilexec "k8s.io/utils/exec"
)

type Converter struct {
}

type NPMCache struct {
	Exec             utilexec.Interface
	Nodename         string
	NsMap            map[string]*npm.Namespace
	PodMap           map[string]*npm.NpmPod
	RawNpMap         map[string]*networkingv1.NetworkPolicy
	ProcessedNpMap   map[string]*networkingv1.NetworkPolicy
	TelemetryEnabled bool
}

var ListMap map[string]string
var SetMap map[string]string
var RequiredChainsMap map[string]bool

func (c *Converter) GetNpmCache() *NPMCache {
	cachObj := &NPMCache{}

	// currently read from file
	byteArray, err := ioutil.ReadFile("dataplaneConverter/npmCache.json")
	if err != nil {
		fmt.Print(err)
	}
	json.Unmarshal(byteArray, &cachObj)
	return cachObj
}

// initialize map of chain name that will be include in the result
func (c *Converter) initRequiredChainMap() {
	RequiredChainsMap = make(map[string]bool)
	for _, chain := range RequiredChains {
		RequiredChainsMap[chain] = true
	}
}

// ConvertIptablesObject returns a JSON object of an iptable go oject
func (c *Converter) ConvertIptablesObject(iptableObj *iptable.Iptables) []byte {
	// iptableJson, err := json.Marshal(iptableObj)
	iptableJson, err := json.MarshalIndent(iptableObj, "", "    ") // pretty print
	if err != nil {
		log.Fatalf("Error occured during marshaling. Error: %s", err.Error())
	}
	return iptableJson
}

// GetJSONRulesFromIptable returns a list of JSON rule object of an iptable
func (c *Converter) GetJSONRulesFromIptable(tableName string, iptableBuffer *bytes.Buffer) [][]byte {
	ruleResListJson := make([][]byte, 0)
	m := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
	}
	pbRuleObj := c.GetProtobufRulesFromIptable(tableName, iptableBuffer)
	for _, rule := range pbRuleObj {
		ruleJson, err := m.Marshal(rule) // pretty print
		if err != nil {
			log.Fatalf("Error occured during marshaling. Error: %s", err.Error())
		}
		ruleResListJson = append(ruleResListJson, ruleJson)
	}
	return ruleResListJson

}

// GetRulesFromIptable returns a list of protobuf rule object of an iptable
func (c *Converter) GetProtobufRulesFromIptable(tableName string, iptableBuffer *bytes.Buffer) []*pb.RuleResponse {
	p := &parser.Parser{}
	npmCache := c.GetNpmCache()
	ListMap = make(map[string]string)
	SetMap = make(map[string]string)
	c.initRequiredChainMap()

	for k := range npmCache.NsMap["all-namespaces"].IpsMgr.ListMap {
		hashedName := util.GetHashedName(k)
		ListMap[hashedName] = k
	}
	for k := range npmCache.NsMap["all-namespaces"].IpsMgr.SetMap {
		hashedName := util.GetHashedName(k)
		SetMap[hashedName] = k
	}
	ipTableObj := p.ParseIptablesObject(tableName, iptableBuffer)
	ruleResList := make([]*pb.RuleResponse, 0)
	for _, v := range ipTableObj.Chains() {
		chainRules := c.getRulesFromChain(v)
		ruleResList = append(ruleResList, chainRules...)
	}

	return ruleResList

}

func (c *Converter) getRulesFromChain(iptableChainObj *iptable.IptablesChain) []*pb.RuleResponse {
	rules := make([]*pb.RuleResponse, 0)
	for _, v := range iptableChainObj.Rules() {
		rule := &pb.RuleResponse{}
		rule.Chain = iptableChainObj.Name()
		if _, ok := RequiredChainsMap[rule.Chain]; !ok {
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

		c.getModulesFromRule(v.Modules(), rule)
		rules = append(rules, rule)

	}
	return rules
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
			return pb.SetType_KEYVALUELABELOFNAMESPACE
		}
		return pb.SetType_KEYLABELOFNAMESPACE
	} else {
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
}

func (c *Converter) getModulesFromRule(m_list []*iptable.Module, ruleRes *pb.RuleResponse) {
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
					if v, ok := ListMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "ListMap")
					} else if v, ok := SetMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "SetMap")
					} else {
						log.Fatalf("Set %v does not exist", ipsetHashedName)
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
					if v, ok := ListMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "ListMap")
					} else if v, ok := SetMap[ipsetHashedName]; ok {
						infoObj.Name = v
						infoObj.Type = c.getSetType(v, "SetMap")
					} else {
						log.Fatalf("Set %v does not exist", ipsetHashedName)
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
					ruleRes.DPort = v[0]
				} else {
					ruleRes.SPort = v[0]
				}
			}
		default:
			continue
		}
	}
}
