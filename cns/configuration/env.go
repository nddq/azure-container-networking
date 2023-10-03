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
	// LabelNodeSwiftV2 is the Node label for Swift V2
	LabelNodeSwiftV2 = "kubernetes.azure.com/podnetwork-multi-tenancy-enabled"
	LabelPodSwiftV2  = "kubernetes.azure.com/pod-network"
	EnvPodV4CIDR     = "POD_V4_CIDR"
	EnvPodV6CIDR     = "POD_V6_CIDR"
	EnvServiceCIDR   = "SERVICE_CIDR"
)

// ErrNodeNameUnset indicates the the $EnvNodeName variable is unset in the environment.
var ErrNodeNameUnset = errors.Errorf("must declare %s environment variable", EnvNodeName)

// ErrPodV4CIDRUnset indicates the the $EnvPodV4CIDR variable is unset in the environment.
var ErrPodV4CIDRUnset = errors.Errorf("must declare %s environment variable", EnvPodV4CIDR)

// ErrPodV6CIDRUnset indicates the the $EnvPodV6CIDR variable is unset in the environment.
var ErrPodV6CIDRUnset = errors.Errorf("must declare %s environment variable", EnvPodV6CIDR)

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

func PodV4CIDR() (string, error) {
	podCIDRv4 := os.Getenv(EnvPodV4CIDR)
	if podCIDRv4 == "" {
		return "", ErrPodV4CIDRUnset
	}
	return podCIDRv4, nil
}

func PodV6CIDR() (string, error) {
	podCIDRv6 := os.Getenv(EnvPodV6CIDR)
	if podCIDRv6 == "" {
		return "", ErrPodV6CIDRUnset
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
