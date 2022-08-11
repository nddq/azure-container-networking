package restserver

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/logger"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/iptables"
	"github.com/Azure/azure-container-networking/network/networkutils"
	goiptables "github.com/coreos/go-iptables/iptables"
)

// nolint
func (service *HTTPRestService) programSNATRules(req *cns.CreateNetworkContainerRequest) (types.ResponseCode, string) {
	service.Lock()
	defer service.Unlock()

	if service.programmedIPtables { // check if iptables has already been programmed
		logger.Printf("[Azure CNS] SNAT IPTables rules already programmed")
		return types.Success, ""
	}

	// Parse primary ip and ipnet from nnc
	ncPrimaryIP, ncIPNet, _ := net.ParseCIDR(req.IPConfiguration.IPSubnet.IPAddress + "/" + fmt.Sprintf("%d", req.IPConfiguration.IPSubnet.PrefixLength))
	ipt, err := goiptables.New()
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to create iptables interface : %v", err)
	}

	chainExist, err := ipt.ChainExists(iptables.Nat, "SWIFT-POSTROUTING")
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to check for existence of SWIFT chain: %v", err)
	}

	if !chainExist { // create and append chain if it doesn't exist
		logger.Printf("[Azure CNS] Creating SWIFT Chain ...")
		err = ipt.NewChain(iptables.Nat, "SWIFT-POSTROUTING")
		if err != nil {
			return types.FailedToRunIPTableCmd, "[Azure CNS] failed to create SWIFT chain : " + err.Error()
		}
		logger.Printf("[Azure CNS] Append SWIFT Chain to POSTROUTING ...")
		err = ipt.Append(iptables.Nat, iptables.Postrouting, "-j", "SWIFT-POSTROUTING")
		if err != nil {
			return types.FailedToRunIPTableCmd, "[Azure CNS] failed to append SWIFT chain : " + err.Error()
		}
	}

	postroutingToSwiftJumpexist, err := ipt.Exists(iptables.Nat, iptables.Postrouting, "-j", "SWIFT-POSTROUTING")
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to check for existence of POSTROUTING to SWIFT chain jump: %v", err)
	}

	snatUDPRuleexist, err := ipt.Exists(iptables.Nat, "SWIFT-POSTROUTING", "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureDNS, "-p", iptables.UDP, "--dport", strconv.Itoa(iptables.DNSPort), "-j", iptables.Snat, "--to", ncPrimaryIP.String())
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to check for existence of SNAT UDP rule : %v", err)
	}

	snatTCPRuleexist, err := ipt.Exists(iptables.Nat, "SWIFT-POSTROUTING", "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureDNS, "-p", iptables.TCP, "--dport", strconv.Itoa(iptables.DNSPort), "-j", iptables.Snat, "--to", ncPrimaryIP.String())
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to check for existence of SNAT TCP rule : %v", err)
	}

	snatIMDSRuleexist, err := ipt.Exists(iptables.Nat, "SWIFT-POSTROUTING", "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureIMDS, "-p", iptables.TCP, "--dport", strconv.Itoa(iptables.HTTPPort), "-j", iptables.Snat, "--to", req.HostPrimaryIP)
	if err != nil {
		return types.UnexpectedError, fmt.Sprintf("[Azure CNS] Error. Failed to check for existence of SNAT IMDS rule : %v", err)
	}
	if postroutingToSwiftJumpexist && snatUDPRuleexist && snatTCPRuleexist && snatIMDSRuleexist {
		logger.Printf("[Azure CNS] SNAT IPTables rules already programmed")
		service.programmedIPtables = true
		return types.Success, ""
	}

	logger.Printf("[Azure CNS] Inserting SNAT UDP rule ...")
	err = ipt.Insert(iptables.Nat, "SWIFT-POSTROUTING", 1, "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureDNS, "-p", iptables.UDP, "--dport", strconv.Itoa(iptables.DNSPort), "-j", iptables.Snat, "--to", ncPrimaryIP.String())
	if err != nil {
		return types.FailedToRunIPTableCmd, "[Azure CNS] failed to inset SNAT UDP rule : " + err.Error()
	}
	logger.Printf("[Azure CNS] Inserting SNAT TCP rule ...")
	err = ipt.Insert(iptables.Nat, "SWIFT-POSTROUTING", 1, "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureDNS, "-p", iptables.TCP, "--dport", strconv.Itoa(iptables.DNSPort), "-j", iptables.Snat, "--to", ncPrimaryIP.String())
	if err != nil {
		return types.FailedToRunIPTableCmd, "[Azure CNS] failed to insert SNAT TCP rule : " + err.Error()
	}
	logger.Printf("[Azure CNS] Inserting SNAT IMDS rule ...")
	err = ipt.Insert(iptables.Nat, "SWIFT-POSTROUTING", 1, "-m", "addrtype", "!", "--dst-type", "local", "-s", ncIPNet.String(), "-d", networkutils.AzureIMDS, "-p", iptables.TCP, "--dport", strconv.Itoa(iptables.HTTPPort), "-j", iptables.Snat, "--to", req.HostPrimaryIP)
	if err != nil {
		return types.FailedToRunIPTableCmd, "[Azure CNS] failed to insert SNAT IMDS rule : " + err.Error()
	}

	service.programmedIPtables = true
	return types.Success, ""
}
