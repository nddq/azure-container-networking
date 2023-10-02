package middlewares

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/crd/multitenancy/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrMTPNCNotReady         = errors.New("mtpnc is not ready")
	ErrInvalidSWIFTv2NICType = errors.New("invalid NIC type for SWIFT v2 scenario")
)

const (
	prefixLength     = 32
	overlayGatewayv4 = "169.254.1.1"
	overlayGatewayV6 = "fe80::1234:5678:9abc"
)

type SWIFTv2Middleware struct {
	Cli client.Client
}

// ValidateIPConfigsRequest validates if pod is multitenant by checking the pod labels, used in SWIFT V2 scenario.
// nolint
func (m *SWIFTv2Middleware) ValidateIPConfigsRequest(ctx context.Context, req *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	// Retrieve the pod from the cluster
	podInfo, err := cns.UnmarshalPodInfo(req.OrchestratorContext)
	if err != nil {
		errBuf := fmt.Sprintf("unmarshalling pod info from ipconfigs request %v failed with error %v", req, err)
		return types.UnexpectedError, errBuf
	}
	podNamespacedName := k8stypes.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
	pod := v1.Pod{}
	if err := m.Cli.Get(ctx, podNamespacedName, &pod); err != nil {
		errBuf := fmt.Sprintf("failed to get pod %v with error %v", podNamespacedName, err)
		return types.UnexpectedError, errBuf
	}

	// check the pod labels for Swift V2, set the request's SecondaryInterfaceSet flag to true.
	if _, ok := pod.Labels[configuration.LabelSwiftV2]; ok {
		req.SecondaryInterfacesExist = true
	}
	return types.Success, ""
}

// GetIPConfig returns the pod's SWIFT V2 IP configuration.
func (m *SWIFTv2Middleware) GetIPConfig(ctx context.Context, podInfo cns.PodInfo) (cns.PodIpInfo, error) {
	// Check if the MTPNC CRD exists for the pod, if not, return error
	mtpnc := v1alpha1.MultitenantPodNetworkConfig{}
	mtpncNamespacedName := k8stypes.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
	if err := m.Cli.Get(ctx, mtpncNamespacedName, &mtpnc); err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get pod's mtpnc from cache : %w", err)
	}

	// Check if the MTPNC CRD is ready. If one of the fields is empty, return error
	if mtpnc.Status.PrimaryIP == "" || mtpnc.Status.MacAddress == "" || mtpnc.Status.NCID == "" || mtpnc.Status.GatewayIP == "" {
		return cns.PodIpInfo{}, ErrMTPNCNotReady
	}
	podIPInfo := cns.PodIpInfo{
		PodIPConfig: cns.IPSubnet{
			IPAddress:    mtpnc.Status.PrimaryIP,
			PrefixLength: prefixLength,
		},
		MacAddress:        mtpnc.Status.MacAddress,
		NICType:           cns.DelegatedVMNIC,
		SkipDefaultRoutes: false,
		// InterfaceName is empty for DelegatedVMNIC
	}

	return podIPInfo, nil
}

// SetRoutes sets the routes for podIPInfo used in SWIFT V2 scenario.
func (m *SWIFTv2Middleware) SetRoutes(podIPInfo *cns.PodIpInfo) error {
	switch podIPInfo.NICType {
	case cns.DelegatedVMNIC:
		// default route via SWIFT v2 interface
		route := cns.Route{
			IPAddress: "0.0.0.0/0",
		}
		podIPInfo.Routes = []cns.Route{route}
	case cns.InfraNIC:
		// Check if IP is v4 or v6
		if net.ParseIP(podIPInfo.PodIPConfig.IPAddress).To4() != nil {
			// route for IPv4 podCIDR traffic
			podCIDRv4, err := configuration.PodV4CIDR()
			if err != nil {
				return fmt.Errorf("failed to get podCIDRv4 from env : %w", err)
			}
			podCIDRv4Route := cns.Route{
				IPAddress:        podCIDRv4,
				GatewayIPAddress: overlayGatewayv4,
			}
			podIPInfo.Routes = []cns.Route{podCIDRv4Route}
		} else {
			// route for IPv6 podCIDR traffic
			podCIDRv6, err := configuration.PodV6CIDR()
			if err != nil {
				return fmt.Errorf("failed to get podCIDRv6 from env : %w", err)
			}
			podCIDRv6Route := cns.Route{
				IPAddress:        podCIDRv6,
				GatewayIPAddress: overlayGatewayV6,
			}
			podIPInfo.Routes = []cns.Route{podCIDRv6Route}
		}
	default:
		return ErrInvalidSWIFTv2NICType
	}
	return nil
}
