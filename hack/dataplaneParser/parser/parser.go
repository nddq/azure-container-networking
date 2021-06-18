package parser

import (
	"bytes"
	"fmt"

	"github.com/Azure/azure-container-networking/hack/dataplaneParser/iptable"
	"github.com/Azure/azure-container-networking/npm/util"
)

type Parser struct {
}

func CreateIptablesObject(tableName string, byteArray []byte) *iptable.Iptables {
	p := &Parser{}
	iptables := &iptable.Iptables{
		Name:   tableName,
		Chains: p.parseIptablesChainObject(tableName, byteArray),
	}
	return iptables
}

func (p *Parser) parseIptablesChainObject(tableName string, byteArray []byte) map[string]*iptable.IptablesChain {
	chainMap := make(map[string]*iptable.IptablesChain)
	tablePrefix := []byte("*" + tableName)
	curReadIndex := 0
	for curReadIndex < len(byteArray) {
		line, nextReadIndex := p.parseLine(curReadIndex, byteArray)
		curReadIndex = nextReadIndex
		if bytes.HasPrefix(line, tablePrefix) {
			break
		}
	}

	for curReadIndex < len(byteArray) {
		line, nextReadIndex := p.parseLine(curReadIndex, byteArray)
		curReadIndex = nextReadIndex
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, util.CommitBytes) || line[0] == '*' {
			break
		} else if line[0] == ':' && len(line) > 1 {
			// We assume that the <line> contains space - chain lines have 3 fields,
			// space delimited. If there is no space, this line will panic.
			spaceIndex := bytes.Index(line, util.SpaceBytes)
			if spaceIndex == -1 {
				panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(line)))
			}
			chainName := string(line[1:spaceIndex])
			if val, ok := chainMap[chainName]; ok {
				val.Data = line
				chainMap[chainName] = val
			} else {
				chainMap[chainName] = &iptable.IptablesChain{
					Name:  chainName,
					Data:  line,
					Rules: make([]*iptable.IptablesRule, 0),
				}
			}
		} else if line[0] == '-' && len(line) > 1 {
			chainName, ruleStartIndex := p.parseChainNameFromRule(line)
			val, ok := chainMap[chainName]
			if !ok {
				val = &iptable.IptablesChain{
					Name:  chainName,
					Data:  []byte{},
					Rules: make([]*iptable.IptablesRule, 0),
				}
			}
			val.Rules = append(val.Rules, p.parseRuleFromLine(line[ruleStartIndex:]))
		}
	}
	return chainMap
}

func (p *Parser) parseLine(readIndex int, byteArray []byte) ([]byte, int) {
	curReadIndex := readIndex

	// consume left spaces
	for curReadIndex < len(byteArray) {
		if byteArray[curReadIndex] == ' ' {
			curReadIndex++
		} else {
			break
		}
	}
	leftLineIndex := curReadIndex
	rightLineIndex := -1

	for ; curReadIndex < len(byteArray); curReadIndex++ {
		if byteArray[curReadIndex] == ' ' {
			if rightLineIndex == -1 {
				rightLineIndex = curReadIndex
			}
		} else if byteArray[curReadIndex] == '\n' || curReadIndex == (len(byteArray)-1) {
			//end of buffer or end of line
			if rightLineIndex == -1 {
				rightLineIndex = curReadIndex
				if curReadIndex == len(byteArray)-1 && byteArray[curReadIndex] != '\n' {
					rightLineIndex++
				}
			}
			return byteArray[leftLineIndex:rightLineIndex], curReadIndex + 1
		} else {
			rightLineIndex = -1
		}

	}
	return nil, curReadIndex
}

func (p *Parser) parseRuleFromLine(byteArray []byte) *iptable.IptablesRule {
	iptableRule := &iptable.IptablesRule{}
	nextIndex := 0
	for nextIndex < len(byteArray) {
		spaceIndex := bytes.Index(byteArray[nextIndex:], util.SpaceBytes)
		if spaceIndex == -1 {
			break
		}
		start := spaceIndex + nextIndex
		flag := string(byteArray[nextIndex:start]) // can be -m, -,j -p
		if flag == util.IptablesProtFlag {
			spaceIndex1 := bytes.Index(byteArray[start+1:], util.SpaceBytes)
			if spaceIndex1 == -1 {
				panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(byteArray)))
			}
			end := start + 1 + spaceIndex1
			protocol := string(byteArray[start+1 : end])
			iptableRule.Protocol = protocol
			nextIndex = end + 1
		} else if flag == util.IptablesJumpFlag {
			//parse target with format -j TARGET (OPTION) (VALUE)
			target := &iptable.Target{}
			n := p.parseTarget(start+1, target, byteArray)
			iptableRule.Target = target
			nextIndex = n

		} else {
			// parse module with -m verb {--option {value}}
			module := &iptable.Module{}
			module.OptionValueMap = make(map[string][]string)
			n := p.parseModule(start+1, module, byteArray)
			iptableRule.Modules = append(iptableRule.Modules, module)
			nextIndex = n
		}
	}
	return iptableRule
}

func (p *Parser) parseTarget(nextIndex int, target *iptable.Target, byteArray []byte) int {
	// TODO: Assume that target is always at the end of every line of rule
	spaceIndex := bytes.Index(byteArray[nextIndex:], util.SpaceBytes)
	if spaceIndex == -1 {
		targetName := string(byteArray[nextIndex:])
		target.Name = targetName
		return len(byteArray)
	}
	targetName := string(byteArray[nextIndex : nextIndex+spaceIndex])
	target.Name = targetName
	start := nextIndex + spaceIndex + 1
	spaceIndex = bytes.Index(byteArray[start:], util.SpaceBytes)
	if spaceIndex == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(byteArray)))
	}
	end := start + spaceIndex
	targetOption := string(byteArray[start:end])
	target.Option = targetOption
	start = end + 1
	end = len(byteArray) - 1
	target.Value = string(byteArray[start:end])
	return end + 1
}

func (p *Parser) parseModule(nextIndex int, module *iptable.Module, byteArray []byte) int {
	spaceIndex := bytes.Index(byteArray[nextIndex:], util.SpaceBytes)
	if spaceIndex == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(byteArray)))
	}
	verb := string(byteArray[nextIndex : nextIndex+spaceIndex])
	module.Verb = verb
	return p.parseOptionAndValue(nextIndex+spaceIndex+1, module, "", byteArray)
}

func (p *Parser) parseOptionAndValue(nextIndex int, module *iptable.Module, curOption string, byteArray []byte) int {
	spaceIndex := bytes.Index(byteArray[nextIndex:], util.SpaceBytes)
	currentOption := curOption
	if spaceIndex == -1 {
		return nextIndex
	}
	v := string(byteArray[nextIndex : nextIndex+spaceIndex])
	if v[:2] == "--" {
		//this is an option
		module.OptionValueMap[v] = make([]string, 0)
		currentOption = v
	} else if len(v) == 2 && v[0] == '-' {
		// this is a new verb
		return nextIndex
	} else {
		//this is a value
		if currentOption == "" {
			panic(fmt.Sprintf("Unexpected chain line in iptables-save output, value have no preceded option: %v", string(byteArray)))
		}
		module.OptionValueMap[currentOption] = append(module.OptionValueMap[currentOption], v)
	}
	nextIndex = nextIndex + spaceIndex + 1
	return p.parseOptionAndValue(nextIndex, module, currentOption, byteArray)

}

func (p *Parser) parseChainNameFromRule(byteArray []byte) (string, int) {
	spaceIndex1 := bytes.Index(byteArray, util.SpaceBytes)
	if spaceIndex1 == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(byteArray)))
	}
	start := spaceIndex1 + 1
	spaceIndex2 := bytes.Index(byteArray[start:], util.SpaceBytes)
	if spaceIndex2 == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(byteArray)))
	}
	end := start + spaceIndex2
	return string(byteArray[start:end]), end + 1
}
