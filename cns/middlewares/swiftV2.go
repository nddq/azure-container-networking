package middlewares

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/crd/multitenancy/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrMTPNCNotReady = errors.New("mtpnc is not ready")

type SWIFTv2Middleware struct {
	Cli client.Client
}

// validateMultitenantIPConfigsRequest validates if pod is multitenant by checking the pod labels, used in SWIFT V2 scenario.
// nolint
func (m *SWIFTv2Middleware) ValidateMultitenantIPConfigsRequest(req *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	// Retrieve the pod from the cluster
	podInfo, err := cns.UnmarshalPodInfo(req.OrchestratorContext)
	if err != nil {
		errBuf := fmt.Sprintf("unmarshalling pod info from ipconfigs request %v failed with error %v", req, err)
		return types.UnexpectedError, errBuf
	}
	podNamespacedName := k8stypes.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
	pod := v1.Pod{}
	if err := m.Cli.Get(context.TODO(), podNamespacedName, &pod); err != nil {
		errBuf := fmt.Sprintf("failed to get pod %v with error %v", podNamespacedName, err)
		return types.UnexpectedError, errBuf
	}

	// check the pod labels for Swift V2, set the request's SecondaryInterfaceSet flag to true.
	if _, ok := pod.Labels[configuration.LabelSwiftV2]; ok {
		req.SecondaryInterfaceSet = true
	}
	return types.Success, ""
}

// GetMultitenantIPConfig returns the IP config for a multitenant pod from the MTPNC CRD
func (m *SWIFTv2Middleware) GetSWIFTv2IPConfig(ctx context.Context, podInfo cns.PodInfo) (cns.PodIpInfo, error) {
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
	podIPInfo := cns.PodIpInfo{}
	podIPInfo.PodIPConfig = cns.IPSubnet{
		IPAddress: mtpnc.Status.PrimaryIP,
	}
	podIPInfo.MACAddress = mtpnc.Status.MacAddress
	podIPInfo.NICType = cns.NICTypeSecondary
	podIPInfo.SkipDefaultRoutes = true

	defaultRoute := cns.Route{
		IPAddress:        mtpnc.Status.PrimaryIP,
		GatewayIPAddress: mtpnc.Status.GatewayIP,
		InterfaceToUse:   "eth1",
	}

	podCIDR, err := configuration.PodCIDR()
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get pod CIDR from environment : %w", err)
	}

	podCIDRRoute := cns.Route{
		IPAddress:      podCIDR,
		InterfaceToUse: "eth0",
	}

	serviceCIDR, err := configuration.ServiceCIDR()
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get service CIDR from environment : %w", err)
	}

	serviceCIDRRoute := cns.Route{
		IPAddress:      serviceCIDR,
		InterfaceToUse: "eth0",
	}
	podIPInfo.Routes = []cns.Route{defaultRoute, podCIDRRoute, serviceCIDRRoute}

	return podIPInfo, nil
}
