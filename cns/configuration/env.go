package configuration

import (
	"os"

	"github.com/pkg/errors"
)

const (
	// EnvNodeName is the NODENAME env var string key.
	EnvNodeName = "NODENAME"
	// EnvNodeIP is the IP of the node running this CNS binary
	EnvNodeIP = "NODE_IP"
	// LabelSwiftV2 is the Node label for Swift V2
	LabelSwiftV2   = "kubernetes.azure.com/podnetwork-multi-tenancy-enabled"
	EnvPodCIDRv4   = "POD_CIDRv4"
	EnvPodCIDRv6   = "POD_CIDRv6"
	EnvServiceCIDR = "SERVICE_CIDR"
)

// ErrNodeNameUnset indicates the the $EnvNodeName variable is unset in the environment.
var ErrNodeNameUnset = errors.Errorf("must declare %s environment variable", EnvNodeName)

// ErrPodCIDRv4Unset indicates the the $EnvPodCIDRv4 variable is unset in the environment.
var ErrPodCIDRv4Unset = errors.Errorf("must declare %s environment variable", EnvPodCIDRv4)

// ErrServiceCIDRUnset indicates the the $EnvServiceCIDR variable is unset in the environment.
var ErrServiceCIDRUnset = errors.Errorf("must declare %s environment variable", EnvServiceCIDR)

// NodeName checks the environment variables for the NODENAME and returns it or an error if unset.
func NodeName() (string, error) {
	nodeName := os.Getenv(EnvNodeName)
	if nodeName == "" {
		return "", ErrNodeNameUnset
	}
	return nodeName, nil
}

// NodeIP returns the value of the NODE_IP environment variable, or empty string if unset.
func NodeIP() string {
	return os.Getenv(EnvNodeIP)
}

func PodCIDRv4() (string, error) {
	podCIDRv4 := os.Getenv(EnvPodCIDRv4)
	if podCIDRv4 == "" {
		return "", ErrPodCIDRv4Unset
	}
	return podCIDRv4, nil
}

func PodCIDRv6() (string, error) {
	podCIDRv6 := os.Getenv(EnvPodCIDRv6)
	if podCIDRv6 == "" {
		return "", ErrPodCIDRv4Unset
	}
	return podCIDRv6, nil
}

func ServiceCIDR() (string, error) {
	serviceCIDR := os.Getenv(EnvServiceCIDR)
	if serviceCIDR == "" {
		return "", ErrServiceCIDRUnset
	}
	return serviceCIDR, nil
}
