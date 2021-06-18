package iptable

import (
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-container-networking/npm/util"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"
)

type Iptables struct {
	Name   string
	Chains map[string]*IptablesChain
}

type IptablesChain struct {
	Name  string
	Data  []byte
	Rules []*IptablesRule
}

type IptablesRule struct {
	Protocol string
	Target   *Target
	Modules  []*Module
}

type Module struct {
	Verb           string
	OptionValueMap map[string][]string
}

type Target struct {
	Name   string
	Option string
	Value  string
}

func grabIptablesFileLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

// grabs iptables v1.6 xtable lock
func GrabIptablesLocks() (*os.File, error) {
	var success bool

	l := &os.File{}
	defer func(l *os.File) {
		// Clean up immediately on failure
		if !success {
			l.Close()
		}
	}(l)

	// Grab 1.6.x style lock.
	l, err := os.OpenFile(util.IptablesLockFile, os.O_CREATE, 0600)
	if err != nil {
		// metrics.SendErrorLogAndMetric(util.IptmID, "Error: failed to open iptables lock file %s.", util.IptablesLockFile)
		return nil, err
	}

	if err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (bool, error) {
		if err := grabIptablesFileLock(l); err != nil {
			return false, nil
		}

		return true, nil
	}); err != nil {
		// metrics.SendErrorLogAndMetric(util.IptmID, "Error: failed to acquire new iptables lock: %v.", err)
		return nil, err
	}

	success = true
	return l, nil
}

func (t *Iptables) PrintIptable() {
	fmt.Printf("IPTABLE NAME - %v\n", t.Name)
	t.printIptableChains()
}

func (t *Iptables) printIptableChains() {
	for k, v := range t.Chains {
		fmt.Printf("IPTABLE CHAIN - %v\n", k)
		fmt.Printf("IPTABLE RULES - %+v\n", v)
	}
}
