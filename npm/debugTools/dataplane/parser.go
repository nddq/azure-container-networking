package dataplane

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/exec"

	"github.com/Azure/azure-container-networking/npm/util"
)

type Parser struct{}

// CreateIptableObject create a Go object from specified iptable. Optional read from iptable-save file
func (p *Parser) ParseIptablesObject(tableName string) *Iptables {
	iptableBuffer := bytes.NewBuffer(nil)
	// TODO: need to get iptable's lock
	cmdArgs := []string{"-t", string(tableName)}
	cmd := exec.Command(util.IptablesSave, cmdArgs...)

	cmd.Stdout = iptableBuffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.Stderr = stderrBuffer

	err := cmd.Run()
	if err != nil {
		_, err = stderrBuffer.WriteTo(iptableBuffer)
		if err != nil {
			panic(err)
		}
	}
	chains := p.parseIptablesChainObject(tableName, iptableBuffer.Bytes())
	return &Iptables{Name: tableName, Chains: chains}
}

func (p *Parser) ParseIptablesObjectFile(tableName string, iptableSaveFile string) *Iptables {
	iptableBuffer := bytes.NewBuffer(nil)
	byteArray, err := ioutil.ReadFile(iptableSaveFile)
	if err != nil {
		fmt.Print(err)
	}
	for _, b := range byteArray {
		iptableBuffer.WriteByte(b)
	}
	chains := p.parseIptablesChainObject(tableName, iptableBuffer.Bytes())
	return &Iptables{Name: tableName, Chains: chains}
}

// parseIptablesChainObject create a map of iptable chain name and iptable chain object
func (p *Parser) parseIptablesChainObject(tableName string, iptableBuffer []byte) map[string]*IptablesChain {
	chainMap := make(map[string]*IptablesChain)
	tablePrefix := []byte("*" + tableName)
	curReadIndex := 0
	for curReadIndex < len(iptableBuffer) {
		line, nextReadIndex := p.parseLine(curReadIndex, iptableBuffer)
		curReadIndex = nextReadIndex
		if bytes.HasPrefix(line, tablePrefix) {
			break
		}
	}

	for curReadIndex < len(iptableBuffer) {
		line, nextReadIndex := p.parseLine(curReadIndex, iptableBuffer)
		curReadIndex = nextReadIndex
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, util.CommitBytes) || line[0] == '*' {
			break
		}
		if line[0] == ':' && len(line) > 1 {
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
				chainMap[chainName] = &IptablesChain{Name: chainName, Data: line, Rules: make([]*IptablesRule, 0)}
			}
		} else if line[0] == '-' && len(line) > 1 {
			chainName, ruleStartIndex := p.parseChainNameFromRule(line)
			val, ok := chainMap[chainName]
			if !ok {
				val = &IptablesChain{chainName, []byte{}, make([]*IptablesRule, 0)}
			}
			val.Rules = append(val.Rules, p.parseRuleFromLine(line[ruleStartIndex:]))
		}
	}
	return chainMap
}

// parseLine parse each line of the read-in byteArray of iptables-save
func (p *Parser) parseLine(readIndex int, iptableBuffer []byte) ([]byte, int) {
	curReadIndex := readIndex

	// consume left spaces
	for curReadIndex < len(iptableBuffer) {
		if iptableBuffer[curReadIndex] != ' ' {
			break
		}
		curReadIndex++
	}
	leftLineIndex := curReadIndex
	rightLineIndex := -1
	lastNonWhiteSpaceIndex := leftLineIndex

	for ; curReadIndex < len(iptableBuffer); curReadIndex++ {
		if iptableBuffer[curReadIndex] == ' ' {
			if rightLineIndex == -1 {
				rightLineIndex = curReadIndex
			}
		} else if iptableBuffer[curReadIndex] == '\n' || curReadIndex == (len(iptableBuffer)-1) {
			// end of buffer or end of line
			if rightLineIndex == -1 {
				rightLineIndex = curReadIndex
				if curReadIndex == len(iptableBuffer)-1 && iptableBuffer[curReadIndex] != '\n' {
					rightLineIndex++
				}
			}
			return iptableBuffer[leftLineIndex:rightLineIndex], curReadIndex + 1
		} else {
			lastNonWhiteSpaceIndex = curReadIndex
			rightLineIndex = -1
		}
	}
	return iptableBuffer[leftLineIndex : lastNonWhiteSpaceIndex+1], curReadIndex // line with right spaces
}

// parseChainNameFromRule gets the chain name from given rule line
func (p *Parser) parseChainNameFromRule(line []byte) (string, int) {
	spaceIndex1 := bytes.Index(line, util.SpaceBytes)
	if spaceIndex1 == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(line)))
	}
	start := spaceIndex1 + 1
	spaceIndex2 := bytes.Index(line[start:], util.SpaceBytes)
	if spaceIndex2 == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(line)))
	}
	end := start + spaceIndex2
	return string(line[start:end]), end + 1
}

// parseRuleFromLine creates an iptable rule object from parsed rule line with chain name excluded from the byte array
func (p *Parser) parseRuleFromLine(ruleLine []byte) *IptablesRule {
	iptableRule := &IptablesRule{}
	nextIndex := 0
	for nextIndex < len(ruleLine) {
		spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
		if spaceIndex == -1 {
			break
		}
		start := spaceIndex + nextIndex           // offset start index
		flag := string(ruleLine[nextIndex:start]) // can be -m, -,j -p
		switch flag {
		case util.IptablesProtFlag:
			spaceIndex1 := bytes.Index(ruleLine[start+1:], util.SpaceBytes)
			if spaceIndex1 == -1 {
				panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(ruleLine)))
			}
			end := start + 1 + spaceIndex1
			protocol := string(ruleLine[start+1 : end])
			iptableRule.Protocol = protocol
			nextIndex = end + 1
		case util.IptablesJumpFlag:
			// parse target with format -j target (option) (value)
			target := &Target{}
			target.OptionValueMap = map[string][]string{}
			n := p.parseTarget(start+1, target, ruleLine)
			iptableRule.Target = target
			nextIndex = n
		case util.IptablesModuleFlag:
			// parse module with format -m verb {--option {value}}
			module := &Module{}
			module.OptionValueMap = map[string][]string{}
			n := p.parseModule(start+1, module, ruleLine)
			iptableRule.Modules = append(iptableRule.Modules, module)
			nextIndex = n
		default:
			nextIndex = p.jumpToNextFlag(start+1, ruleLine)
			continue
		}
	}
	return iptableRule
}

// handle unrecognized flags
func (p *Parser) jumpToNextFlag(nextIndex int, ruleLine []byte) int {
	spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
	if spaceIndex == -1 {
		nextIndex = nextIndex + spaceIndex + 1
		return nextIndex
	}
	ruleElement := string(ruleLine[nextIndex : nextIndex+spaceIndex])
	if len(ruleElement) >= 2 {
		if ruleElement[0] == '-' {
			if ruleElement[1] == '-' {
				// this is an option
				nextIndex = nextIndex + spaceIndex + 1
				// recursively parsing unrecognized flag's options and their value until a new flag is encounter
				return p.jumpToNextFlag(nextIndex, ruleLine)
			}
			// this is a new flag
			return nextIndex
		}
	}
	nextIndex = nextIndex + spaceIndex + 1
	return p.jumpToNextFlag(nextIndex, ruleLine)
}

func (p *Parser) parseTarget(nextIndex int, target *Target, ruleLine []byte) int {
	// TODO: Assume that target is always at the end of every line of rule
	spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
	if spaceIndex == -1 {
		targetName := string(ruleLine[nextIndex:])
		target.Name = targetName
		return len(ruleLine)
	}
	targetName := string(ruleLine[nextIndex : nextIndex+spaceIndex])
	target.Name = targetName
	return p.parseTargetOptionAndValue(nextIndex+spaceIndex+1, target, "", ruleLine)
}

func (p *Parser) parseTargetOptionAndValue(nextIndex int, target *Target, curOption string, ruleLine []byte) int {
	spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
	currentOption := curOption
	if spaceIndex == -1 {
		if currentOption == "" {
			panic(fmt.Sprintf("Unexpected chain line in iptables-save output, value have no preceded option: %v", string(ruleLine)))
		}
		v := string(ruleLine[nextIndex:]) // TODO: assume that target is always at the end of each rule line
		optionValueMap := target.OptionValueMap
		optionValueMap[currentOption] = append(optionValueMap[currentOption], v)
		nextIndex = nextIndex + spaceIndex + 1
		return nextIndex
	}
	ruleElement := string(ruleLine[nextIndex : nextIndex+spaceIndex])
	if len(ruleElement) >= 2 {
		if ruleElement[0] == '-' {
			if ruleElement[1] == '-' {
				// this is an option
				currentOption = ruleElement[2:]
				target.OptionValueMap[currentOption] = make([]string, 0)
				nextIndex = nextIndex + spaceIndex + 1
				// recursively parsing options and their value until a new flag is encounter
				return p.parseTargetOptionAndValue(nextIndex, target, currentOption, ruleLine)
			}
			// this is a new flag
			return nextIndex
		}
	}
	// this is a value
	if currentOption == "" {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output, value have no preceded option: %v", string(ruleLine)))
	}
	target.OptionValueMap[currentOption] = append(target.OptionValueMap[currentOption], ruleElement)
	nextIndex = nextIndex + spaceIndex + 1
	return p.parseTargetOptionAndValue(nextIndex, target, currentOption, ruleLine)
}

func (p *Parser) parseModule(nextIndex int, module *Module, ruleLine []byte) int {
	spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
	if spaceIndex == -1 {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output: %v", string(ruleLine)))
	}
	verb := string(ruleLine[nextIndex : nextIndex+spaceIndex])
	module.Verb = verb
	return p.parseModuleOptionAndValue(nextIndex+spaceIndex+1, module, "", ruleLine, true)
}

func (p *Parser) parseModuleOptionAndValue(nextIndex int, module *Module, curOption string, ruleLine []byte, included bool) int {
	// TODO: Assume that options and values don't locate at the end of a line
	spaceIndex := bytes.Index(ruleLine[nextIndex:], util.SpaceBytes)
	currentOption := curOption
	if spaceIndex == -1 {
		v := string(ruleLine[nextIndex:])
		if len(v) > 1 && v[:2] == "--" {
			// option with no value at end of line
			module.OptionValueMap[v[2:]] = make([]string, 0)
			nextIndex = nextIndex + spaceIndex + 1
			return nextIndex
		}
		// else this is a value at end of line
		if currentOption == "" {
			panic(fmt.Sprintf("Unexpected chain line in iptables-save output, value have no preceded option: %v", string(ruleLine)))
		}
		module.OptionValueMap[currentOption] = append(module.OptionValueMap[currentOption], v)
		nextIndex = nextIndex + spaceIndex + 1
		return nextIndex
	}
	ruleElement := string(ruleLine[nextIndex : nextIndex+spaceIndex])
	if ruleElement == "!" {
		// negation to options
		nextIndex = nextIndex + spaceIndex + 1
		return p.parseModuleOptionAndValue(nextIndex, module, currentOption, ruleLine, false)
	}

	if len(ruleElement) >= 2 {
		if ruleElement[0] == '-' {
			if ruleElement[1] == '-' {
				// this is an option
				currentOption = ruleElement[2:]
				if !included {
					currentOption = util.NegationPrefix + currentOption
				}
				module.OptionValueMap[currentOption] = make([]string, 0)
				nextIndex = nextIndex + spaceIndex + 1
				// recursively parsing options and their value until a new flag is encounter
				return p.parseModuleOptionAndValue(nextIndex, module, currentOption, ruleLine, true)
			}
			return nextIndex
		}
	}
	// this is a value
	if currentOption == "" {
		panic(fmt.Sprintf("Unexpected chain line in iptables-save output, value have no preceded option: %v", string(ruleLine)))
	}
	module.OptionValueMap[currentOption] = append(module.OptionValueMap[currentOption], ruleElement)
	nextIndex = nextIndex + spaceIndex + 1
	return p.parseModuleOptionAndValue(nextIndex, module, currentOption, ruleLine, true)
}
