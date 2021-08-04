package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/npm"
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

// Initialize NPM cache from file
func (c *Converter) NpmCacheFromFile(npmCacheJSONFile string) error {
	c.NPMCache = &NPMCache{}
	// for dev
	byteArray, err := ioutil.ReadFile(npmCacheJSONFile)
	if err != nil {
		return fmt.Errorf("error occurred during reading in file : %w", err)
	}
	err = json.Unmarshal(byteArray, c.NPMCache)
	if err != nil {
		return fmt.Errorf("error occurred during unmarshalling : %w", err)
	}
	return nil
}

// Initialize NPM cache from node
func (c *Converter) NpmCache() error {
	c.NPMCache = &NPMCache{}
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://localhost:10091/npm/v1/debug/manager",
		nil,
	)
	if err != nil {
		return fmt.Errorf("error occurred during creating http request : %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error occurred during requesting NPM Cache : %w", err)
	}
	defer resp.Body.Close()
	byteArray, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error occurred during reading response's data : %w", err)
	}
	err = json.Unmarshal(byteArray, c.NPMCache)
	if err != nil {
		return fmt.Errorf("error occurred during unmarshalling : %w", err)
	}
	return nil
}

// Initialize converter from file
func (c *Converter) initConverterFile(npmCacheJSONFile string) error {
	err := c.NpmCacheFromFile(npmCacheJSONFile)
	if err != nil {
		return fmt.Errorf("error occurred during initialize converter : %w", err)
	}
	c.initConverterMaps()
	return nil
}

// Initialize converter from node
func (c *Converter) initConverter() error {
	err := c.NpmCache()
	if err != nil {
		return fmt.Errorf("error occurred during initialize converter : %w", err)
	}
	c.initConverterMaps()

	return nil
}

// Initialize all converter's maps
func (c *Converter) initConverterMaps() {
	c.RequiredChainsMap = make(map[string]bool)
	for _, chain := range RequiredChains {
		c.RequiredChainsMap[chain] = true
	}
	c.ListMap = make(map[string]string)
	c.SetMap = make(map[string]string)

	for k := range c.NPMCache.NsMap["all-namespaces"].IpsMgr.ListMap {
		hashedName := util.GetHashedName(k)
		c.ListMap[hashedName] = k
	}
	for k := range c.NPMCache.NsMap["all-namespaces"].IpsMgr.SetMap {
		hashedName := util.GetHashedName(k)
		c.SetMap[hashedName] = k
	}
}

// Get a list of json rules from files
func (c *Converter) GetJSONRulesFromIptableFile(
	tableName string,
	npmCacheFile string,
	iptableSaveFile string,
) ([][]byte, error) {

	pbRuleObj, err := c.GetProtobufRulesFromIptableFile(tableName, npmCacheFile, iptableSaveFile)
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting JSON rules from iptables : %w", err)
	}
	return c.jsonRuleList(pbRuleObj)
}

// Get a list of json rules from node
func (c *Converter) GetJSONRulesFromIptables(tableName string) ([][]byte, error) {
	pbRuleObj, err := c.GetProtobufRulesFromIptable(tableName)
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting JSON rules from iptables : %w", err)
	}
	return c.jsonRuleList(pbRuleObj)
}

// Convert list of protobuf rules to list of JSON rules
func (c *Converter) jsonRuleList(pbRuleObj []*pb.RuleResponse) ([][]byte, error) {
	ruleResListJSON := make([][]byte, 0)
	m := protojson.MarshalOptions{
		Indent:          "  ",
		EmitUnpopulated: true,
	}
	for _, rule := range pbRuleObj {
		ruleJSON, err := m.Marshal(rule) // pretty print
		if err != nil {
			return nil, fmt.Errorf("error occurred during marshaling : %w", err)
		}
		ruleResListJSON = append(ruleResListJSON, ruleJSON)
	}
	return ruleResListJSON, nil
}

// Get a list of protobuf rules from files
func (c *Converter) GetProtobufRulesFromIptableFile(
	tableName string,
	npmCacheFile string,
	iptableSaveFile string,
) ([]*pb.RuleResponse, error) {

	err := c.initConverterFile(npmCacheFile)
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting protobuf rules from iptables : %w", err)
	}

	p := &Parser{}
	ipTableObj := p.ParseIptablesObjectFile(tableName, iptableSaveFile)
	ruleResList, err := c.pbRuleList(ipTableObj)
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting protobuf rules from iptables : %w", err)
	}

	return ruleResList, nil
}

// Get a list of protobuf rules from node
func (c *Converter) GetProtobufRulesFromIptable(tableName string) ([]*pb.RuleResponse, error) {
	err := c.initConverter()
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting protobuf rules from iptables : %w", err)
	}

	p := &Parser{}
	ipTableObj := p.ParseIptablesObject(tableName)
	ruleResList, err := c.pbRuleList(ipTableObj)
	if err != nil {
		return nil, fmt.Errorf("error occurred during getting protobuf rules from iptables : %w", err)
	}

	return ruleResList, nil
}

// Create a list of protobuf rules from iptable
func (c *Converter) pbRuleList(ipTableObj *Iptables) ([]*pb.RuleResponse, error) {
	ruleResList := make([]*pb.RuleResponse, 0)
	for _, v := range ipTableObj.Chains {
		chainRules, err := c.getRulesFromChain(v)
		if err != nil {
			return nil, fmt.Errorf("error occurred during getting protobuf rule list : %w", err)
		}
		ruleResList = append(ruleResList, chainRules...)
	}

	return ruleResList, nil
}

func (c *Converter) getRulesFromChain(iptableChainObj *IptablesChain) ([]*pb.RuleResponse, error) {
	rules := make([]*pb.RuleResponse, 0)
	for _, v := range iptableChainObj.Rules {
		rule := &pb.RuleResponse{}
		rule.Chain = iptableChainObj.Name
		if _, ok := c.RequiredChainsMap[rule.Chain]; !ok {
			continue
		}
		rule.Protocol = v.Protocol
		switch v.Target.Name {
		case "MARK":
			rule.Allowed = true
		case "DROP":
			rule.Allowed = false
		default:
			// ignore other targets
			continue
		}
		direction := c.getRuleDirection(iptableChainObj.Name)
		if direction >= 0 {
			rule.Direction = direction
		}

		err := c.getModulesFromRule(v.Modules, rule)
		if err != nil {
			return nil, fmt.Errorf("error occurred during getting rules from chain : %w", err)
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
	}
	return pb.Direction_UNDEFINED
}

func (c *Converter) getSetType(name string, m string) pb.SetType {
	// TODO: Handle CIDR blocks
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
	if matched, _ := regexp.MatchString(`(?i)[^ ]+-in-ns-[^ ]+-\d(out|in)\b`, name); matched {
		return pb.SetType_CIDRBLOCKS
	}
	return pb.SetType_KEYLABELOFPOD
}

func (c *Converter) getModulesFromRule(moduleList []*Module, ruleRes *pb.RuleResponse) error {
	ruleRes.SrcList = make([]*pb.RuleResponse_SetInfo, 0)
	ruleRes.DstList = make([]*pb.RuleResponse_SetInfo, 0)
	ruleRes.UnsortedIpset = make(map[string]string)
	for _, module := range moduleList {
		switch module.Verb {
		case "set":
			// set module
			OptionValueMap := module.OptionValueMap
			for option, values := range OptionValueMap {
				switch option {
				case "match-set":
					infoObj := &pb.RuleResponse_SetInfo{}

					err := c.populateSetInfoObj(infoObj, values, ruleRes)
					if err != nil {
						return fmt.Errorf("error occurred during getting modules from rules : %w", err)
					}
					infoObj.Included = true

				case "not-match-set":
					infoObj := &pb.RuleResponse_SetInfo{}
					err := c.populateSetInfoObj(infoObj, values, ruleRes)
					if err != nil {
						return fmt.Errorf("error occurred during getting modules from rules : %w", err)
					}
					infoObj.Included = false
				default:
					// todo add warning log
					log.Printf("%v option have not been implemented\n", option)
					continue
				}
			}

		case "tcp", "udp":
			OptionValueMap := module.OptionValueMap
			for k, v := range OptionValueMap {
				if k == "dport" {
					portNum, _ := strconv.ParseInt(v[0], Base, Bitsize)
					ruleRes.DPort = int32(portNum)
				} else {
					portNum, _ := strconv.ParseInt(v[0], Base, Bitsize)
					ruleRes.SPort = int32(portNum)
				}
			}
		default:
			continue
		}
	}
	return nil
}

func (c *Converter) populateSetInfoObj(
	infoObj *pb.RuleResponse_SetInfo,
	values []string,
	ruleRes *pb.RuleResponse,
) error {

	ipsetHashedName := values[0]
	ipsetOrigin := values[1]
	infoObj.HashedSetName = ipsetHashedName
	if v, ok := c.ListMap[ipsetHashedName]; ok {
		infoObj.Name = v
		infoObj.Type = c.getSetType(v, "ListMap")
	} else if v, ok := c.SetMap[ipsetHashedName]; ok {
		infoObj.Name = v
		infoObj.Type = c.getSetType(v, "SetMap")
		if infoObj.Type == pb.SetType_CIDRBLOCKS {
			handleCIDRBlockSetType(infoObj)
		}
	} else {
		return fmt.Errorf("set %v does not exist", ipsetHashedName)
	}

	if len(ipsetOrigin) > MinUnsortedIPSetLength {
		ruleRes.UnsortedIpset[ipsetHashedName] = ipsetOrigin
	}
	if strings.Contains(ipsetOrigin, "src") {
		ruleRes.SrcList = append(ruleRes.SrcList, infoObj)
	} else {
		ruleRes.DstList = append(ruleRes.DstList, infoObj)
	}
	return nil
}

// populate CIDRBlock set's content with ip addresses
func handleCIDRBlockSetType(setInfoObj *pb.RuleResponse_SetInfo) {
	ipsetBuffer := bytes.NewBuffer(nil)
	cmdArgs := []string{"list", setInfoObj.HashedSetName}
	cmd := exec.Command(util.Ipset, cmdArgs...) //nolint:gosec

	cmd.Stdout = ipsetBuffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.Stderr = stderrBuffer

	err := cmd.Run()
	if err != nil {
		_, err = stderrBuffer.WriteTo(ipsetBuffer)
		if err != nil {
			panic(err)
		}
	}
	curReadIndex := 0
	p := Parser{}

	// finding the members field
	for curReadIndex < len(ipsetBuffer.Bytes()) {
		line, nextReadIndex := p.parseLine(curReadIndex, ipsetBuffer.Bytes())
		curReadIndex = nextReadIndex
		if bytes.HasPrefix(line, util.MembersBytes) {
			break
		}
	}
	for curReadIndex < len(ipsetBuffer.Bytes()) {
		member, nextReadIndex := p.parseLine(curReadIndex, ipsetBuffer.Bytes())
		setInfoObj.Contents = append(setInfoObj.Contents, string(member))
		curReadIndex = nextReadIndex
	}
}
