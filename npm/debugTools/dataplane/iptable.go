package dataplane

import (
	"fmt"
	"strings"
)

// Iptables struct
type Iptables struct {
	Name   string
	Chains map[string]*IptablesChain
}

// IptablesChain struct
type IptablesChain struct {
	Name  string
	Data  []byte
	Rules []*IptablesRule
}

// IptablesRule struct
type IptablesRule struct {
	Protocol string
	Target   *Target
	Modules  []*Module
}

// Module struct
type Module struct {
	Verb           string
	OptionValueMap map[string][]string
}

// Target struct
type Target struct {
	Name           string
	OptionValueMap map[string][]string
}

// for debugging
func (t *Iptables) String() string {
	return fmt.Sprintf("IPTABLE NAME - %v\n%s\n", t.Name, t.printIptableChains())
}

func (t *Iptables) printIptableChains() string {
	var ret strings.Builder
	for k, v := range t.Chains {
		ret.WriteString(fmt.Sprintf("\tIPTABLE CHAIN NAME - %v\n%s\n", k, t.printIptableChainRules(v)))
	}
	return ret.String()
}

func (t *Iptables) printIptableChainRules(chain *IptablesChain) string {
	var ret strings.Builder
	for k, v := range chain.Rules {
		ret.WriteString(fmt.Sprintf("\t\tRULE %v\n", k))
		ret.WriteString(fmt.Sprintf("\t\t\tRULE'S PROTOCOL - %v\n", v.Protocol))
		ret.WriteString(t.printIptableRuleModules(v.Modules))
		ret.WriteString(t.printIptableRuleTarget(v.Target))
	}
	return ret.String()
}

func (t *Iptables) printIptableRuleModules(mList []*Module) string {
	var ret strings.Builder
	ret.WriteString("\t\t\tRULE'S MODULES\n")

	for i, v := range mList {
		ret.WriteString(fmt.Sprintf("\t\t\t\tModule %v\n", i))
		ret.WriteString(fmt.Sprintf("\t\t\t\t\tVerb - %v\n", v.Verb))
		ret.WriteString(fmt.Sprintf("\t\t\t\t\tOptionValueMap - %+v\n", v.OptionValueMap))
	}
	return ret.String()
}

func (t *Iptables) printIptableRuleTarget(target *Target) string {
	var ret strings.Builder
	ret.WriteString("\t\t\tRULE'S TARGET\n")
	ret.WriteString(fmt.Sprintf("\t\t\t\tNAME - %v\n", target.Name))
	ret.WriteString(fmt.Sprintf("\t\t\t\tOptionValueMap - %+v\n", target.OptionValueMap))
	return ret.String()
}
