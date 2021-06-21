package converter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-container-networking/hack/dataplaneParser/iptable"
	"github.com/Azure/azure-container-networking/hack/dataplaneParser/parser"
)

type Converter struct {
}

type IptableResponse struct {
	Name   string `json:"name"`
	Chains []struct {
		Name  string `json:"name"`
		Rules []struct {
			Protocol string `json:"protocol"`
			Target   struct {
				Name   string `json:"name"`
				Option string `json:"option"`
				Value  string `json:"value"`
			} `json:"target"`
			Modules []struct {
				Verb           string `json:"verb"`
				OptionValueMap []struct {
					Option string   `json:"option"`
					Values []string `json:"values"`
				} `json:"optionValueMap"`
			} `json:"modules"`
		} `json:"rules"`
	} `json:"chains"`
}

type RuleResponse struct {
	Chain         string            `json:"chain"`
	SrcList       []string          `json:"srcList"`
	DstList       []string          `json:"dstList"`
	Protocol      string            `json:"protocol"`
	DPort         string            `json:"dport"`
	SPort         string            `json:"sport"`
	Allowed       bool              `json:"allowed"`
	Direction     string            `json:"direction"`
	UnsortedIpset map[string]string `json:"unsortedIpset"` //key: ipset name, value: src,dst or dst,dst
}

type Direction int

func (d Direction) String() string {
	return [...]string{"EGRESS", "INGRESS"}[d]
}

const (
	EGRESS Direction = iota
	INGRESS
)

// ConvertIptablesObject converts iptable object to JSON
func (c *Converter) ConvertIptablesObject(iptableObj *iptable.Iptables) IptableResponse {
	res := &IptableResponse{}
	return *res
}

func (c *Converter) getModulesFromRule(m_list []*iptable.Module, ruleRes *RuleResponse) {
	ruleRes.SrcList = make([]string, 0)
	ruleRes.DstList = make([]string, 0)
	ruleRes.UnsortedIpset = make(map[string]string)
	for _, m := range m_list {
		switch m.Verb {
		case "set":
			//set module
			OptionValueMap := m.OptionValueMap
			ipsetName := OptionValueMap["match-set"][0]
			ipsetOrigin := OptionValueMap["match-set"][1]
			if len(ipsetOrigin) > 3 {
				ruleRes.UnsortedIpset[ipsetName] = ipsetOrigin
			}
			if strings.Contains(ipsetOrigin, "src") {
				ruleRes.SrcList = append(ruleRes.SrcList, ipsetName)
			} else {
				ruleRes.DstList = append(ruleRes.DstList, ipsetName)
			}
		case "tcp":
			// tcp module TODO: other protocol
			OptionValueMap := m.OptionValueMap
			for k, v := range OptionValueMap {
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

func (c *Converter) getRuleDirection(iptableChainObjName string) Direction {
	if strings.Contains(iptableChainObjName, "EGRESS") {
		return EGRESS
	} else if strings.Contains(iptableChainObjName, "INGRESS") {
		return INGRESS
	} else {
		return -1
	}
}

func (c *Converter) getRulesFromChain(iptableChainObj *iptable.IptablesChain) []*RuleResponse {
	rules := make([]*RuleResponse, 0)
	for _, v := range iptableChainObj.Rules {
		rule := &RuleResponse{}
		rule.Chain = iptableChainObj.Name
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
		if direction > 0 {
			rule.Direction = fmt.Sprint(direction)
		}

		c.getModulesFromRule(v.Modules, rule)
		rules = append(rules, rule)

	}
	return rules
}

func (c *Converter) GetRulesFromIptable(tableName string, iptableBuffer *bytes.Buffer) [][]byte {
	ret := make([][]byte, 0)
	p := &parser.Parser{}
	ipTableObj := p.ParseIptablesObject(tableName, iptableBuffer)
	for _, v := range ipTableObj.Chains {
		chainRules := c.getRulesFromChain(v)
		for _, v := range chainRules {
			// r, err := json.Marshal(v)
			r, err := json.MarshalIndent(v, "", "    ") //pretty print
			if err != nil {
				fmt.Println(err)
				return nil
			}
			ret = append(ret, r)
		}
	}
	return ret
}
