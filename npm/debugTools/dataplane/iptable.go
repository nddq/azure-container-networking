package dataplane

import (
	"fmt"
	"strings"
)

type Iptables struct {
	name   string
	chains map[string]*IptablesChain
}

// NewIptables is the constructor for iptables
func NewIptables(name string, chains map[string]*IptablesChain) *Iptables {
	iptable := &Iptables{}
	iptable.name = name
	iptable.chains = chains
	return iptable
}

func (t *Iptables) Name() string {
	return t.name
}

func (t *Iptables) SetName(name string) {
	t.name = name
}

func (t *Iptables) Chains() map[string]*IptablesChain {
	return t.chains
}

func (t *Iptables) SetChains(chain_m map[string]*IptablesChain) {
	t.chains = chain_m
}

type IptablesChain struct {
	name  string
	data  []byte
	rules []*IptablesRule
}

func NewIptablesChain(name string, data []byte, rules []*IptablesRule) *IptablesChain {
	iptableChain := &IptablesChain{}
	iptableChain.name = name
	iptableChain.data = data
	iptableChain.rules = rules
	return iptableChain
}

func (c *IptablesChain) Name() string {
	return c.name
}

func (c *IptablesChain) SetName(name string) {
	c.name = name
}

func (c *IptablesChain) Data() []byte {
	return c.data
}

func (c *IptablesChain) SetData(d []byte) {
	c.data = d
}

func (c *IptablesChain) Rules() []*IptablesRule {
	return c.rules
}

func (c *IptablesChain) SetRules(rules []*IptablesRule) {
	c.rules = rules
}

type IptablesRule struct {
	protocol string
	target   *Target
	modules  []*Module
}

func NewIptablesRule(protocol string, target *Target, modules []*Module) *IptablesRule {
	iptablerule := &IptablesRule{}
	iptablerule.protocol = protocol
	iptablerule.target = target
	iptablerule.modules = modules
	return iptablerule
}

func (r *IptablesRule) Protocol() string {
	return r.protocol
}

func (r *IptablesRule) SetProtocol(p string) {
	r.protocol = p
}

func (r *IptablesRule) Target() *Target {
	return r.target
}

func (r *IptablesRule) SetTarget(t *Target) {
	r.target = t
}

func (r *IptablesRule) Modules() []*Module {
	return r.modules
}

func (r *IptablesRule) SetModules(mList []*Module) {
	r.modules = mList
}

type Module struct {
	verb           string
	optionValueMap map[string][]string
}

func NewModule(verb string, optionValueMap map[string][]string) *Module {
	module := &Module{}
	module.verb = verb
	module.optionValueMap = optionValueMap
	return module
}

func (m *Module) Verb() string {
	return m.verb
}

func (m *Module) SetVerb(v string) {
	m.verb = v
}

func (m *Module) OptionValueMap() map[string][]string {
	return m.optionValueMap
}

func (m *Module) SetOptionValueMap(optionvaluemap map[string][]string) {
	m.optionValueMap = optionvaluemap
}

type Target struct {
	name           string
	optionValueMap map[string][]string
}

func NewTarget(name string, optionValueMap map[string][]string) *Target {
	target := &Target{}
	target.name = name
	target.optionValueMap = optionValueMap
	return target
}

func (t *Target) Name() string {
	return t.name
}

func (t *Target) SetName(name string) {
	t.name = name
}

func (t *Target) OptionValueMap() map[string][]string {
	return t.optionValueMap
}

func (t *Target) SetOptionValueMap(optionvaluemap map[string][]string) {
	t.optionValueMap = optionvaluemap
}

// for debugging
func (t *Iptables) String() string {
	return fmt.Sprintf("IPTABLE NAME - %v\n%s\n", t.Name(), t.printIptableChains())
}

func (t *Iptables) printIptableChains() string {
	var ret strings.Builder
	for k, v := range t.Chains() {
		ret.WriteString(fmt.Sprintf("\tIPTABLE CHAIN NAME - %v\n%s\n", k, t.printIptableChainRules(v)))
	}
	return ret.String()
}

func (t *Iptables) printIptableChainRules(chain *IptablesChain) string {
	var ret strings.Builder
	for k, v := range chain.Rules() {
		ret.WriteString(fmt.Sprintf("\t\tRULE %v\n", k))
		ret.WriteString(fmt.Sprintf("\t\t\tRULE'S PROTOCOL - %v\n", v.Protocol()))
		ret.WriteString(t.printIptableRuleModules(v.Modules()))
		ret.WriteString(t.printIptableRuleTarget(v.Target()))
	}
	return ret.String()
}

func (t *Iptables) printIptableRuleModules(mList []*Module) string {
	var ret strings.Builder
	ret.WriteString("\t\t\tRULE'S MODULES\n")

	for i, v := range mList {
		ret.WriteString(fmt.Sprintf("\t\t\t\tModule %v\n", i))
		ret.WriteString(fmt.Sprintf("\t\t\t\t\tVerb - %v\n", v.Verb()))
		ret.WriteString(fmt.Sprintf("\t\t\t\t\tOptionValueMap - %+v\n", v.OptionValueMap()))
	}
	return ret.String()
}

func (t *Iptables) printIptableRuleTarget(target *Target) string {
	var ret strings.Builder
	ret.WriteString("\t\t\tRULE'S TARGET\n")
	ret.WriteString(fmt.Sprintf("\t\t\t\tNAME - %v\n", target.Name()))
	ret.WriteString(fmt.Sprintf("\t\t\t\tOptionValueMap - %+v\n", target.OptionValueMap()))
	return ret.String()
}
