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
	LabelSwiftV2   = "kubernetes.azure.com/podnetwork-multi-tenancy"
	EnvPodCIDR     = "POD_CIDR"
	EnvServiceCIDR = "SERVICE_CIDR"
)

// ErrNodeNameUnset indicates the the $EnvNodeName variable is unset in the environment.
var ErrNodeNameUnset = errors.Errorf("must declare %s environment variable", EnvNodeName)

// ErrNodeIPUnset indicates the the $EnvNodeIP variable is unset in the environment.
var ErrPodCIDRUnset = errors.Errorf("must declare %s environment variable", EnvPodCIDR)

// ErrNodeIPUnset indicates the the $EnvNodeIP variable is unset in the environment.
var ErrServiceCIDRUnset = errors.Errorf("must declare %s environment variable", EnvPodCIDR)

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

func PodCIDR() (string, error) {
	podCIDR := os.Getenv(EnvPodCIDR)
	if podCIDR == "" {
		return "", ErrPodCIDRUnset
	}
	return podCIDR, nil
}

func ServiceCIDR() (string, error) {
	serviceCIDR := os.Getenv(EnvServiceCIDR)
	if serviceCIDR == "" {
		return "", ErrServiceCIDRUnset
	}
	return serviceCIDR, nil
}
