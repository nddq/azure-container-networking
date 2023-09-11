package middlewares

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/types"
	"github.com/Azure/azure-container-networking/crd/multitenancy/api/v1alpha1"
	"github.com/Azure/azure-container-networking/crd/nodenetworkconfig/api/v1alpha"
	v1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrMTPNCNotReady = errors.New("mtpnc is not ready")

type SWIFTv2Middleware struct {
	// TODO: implement
	// need cached scoped client for pods
	// need client for MTPNC CRD for x-ref pods
	cli client.Client
}

func NewSWIFTv2Middleware(cli client.Client) *SWIFTv2Middleware {
	return &SWIFTv2Middleware{
		cli: cli,
	}
}

// Return the validator function for the middleware
func (m *SWIFTv2Middleware) Validator() cns.IPConfigValidator {
	return m.validateMultitenantIPConfigsRequest
}

// validateMultitenantIPConfigsRequest validates if pod is multitenant
// nolint
func (m *SWIFTv2Middleware) validateMultitenantIPConfigsRequest(req *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	// Retrieve the pod from the cluster
	podInfo, err := cns.UnmarshalPodInfo(req.OrchestratorContext)
	if err != nil {
		errBuf := fmt.Sprintf("unmarshalling pod info from ipconfigs request %v failed with error %v", req, err)
		return types.UnexpectedError, errBuf
	}
	podNamespacedName := k8stypes.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
	pod := v1.Pod{}
	err = m.cli.Get(context.TODO(), podNamespacedName, &pod)
	if err != nil {
		errBuf := fmt.Sprintf("failed to get pod %v with error %v", podNamespacedName, err)
		return types.UnexpectedError, errBuf
	}

	// check the pod labels for Swift V2, enrich the request with the multitenant flag. TBD on the label
	if _, ok := pod.Labels[configuration.LabelSwiftV2]; ok {
		req.Multitenant = true
	}
	return types.Success, ""
}

// GetMultitenantIPConfig returns the IP config for a multitenant pod from the MTPNC CRD
func (m *SWIFTv2Middleware) GetSWIFTv2IPConfig(podInfo cns.PodInfo) (cns.PodIpInfo, error) {
	// Check if the MTPNC CRD exists for the pod, if not, return error
	mtpnc := v1alpha1.MultitenantPodNetworkConfig{}
	mtpncNamespacedName := k8stypes.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
	err := m.cli.Get(context.Background(), mtpncNamespacedName, &mtpnc)
	if err != nil {
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
	podIPInfo.AddressType = cns.Multitenant
	podIPInfo.IsDefaultInterface = true

	defaultRoute := cns.Route{
		IPAddress:        mtpnc.Status.PrimaryIP,
		GatewayIPAddress: mtpnc.Status.GatewayIP,
		InterfaceToUse:   "eth1",
	}

	nnc := v1alpha.NodeNetworkConfig{}
	nodeName, err := configuration.NodeName()
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get node name : %w", err)
	}
	nncNamespacedName := k8stypes.NamespacedName{Namespace: "kube-system", Name: nodeName}
	err = m.cli.Get(context.Background(), nncNamespacedName, &nnc)
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get node network config : %w", err)
	}

	podCIDR, err := configuration.PodCIDR()
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get pod CIDR from environment : %w", err)
	}

	podCIDRRoute := cns.Route{
		IPAddress:        podCIDR,
		GatewayIPAddress: nnc.Status.NetworkContainers[0].DefaultGateway,
		InterfaceToUse:   "eth0",
	}

	serviceCIDR, err := configuration.ServiceCIDR()
	if err != nil {
		return cns.PodIpInfo{}, fmt.Errorf("failed to get service CIDR from environment : %w", err)
	}

	serviceCIDRRoute := cns.Route{
		IPAddress:        serviceCIDR,
		GatewayIPAddress: nnc.Status.NetworkContainers[0].DefaultGateway,
		InterfaceToUse:   "eth0",
	}
	podIPInfo.Routes = []cns.Route{defaultRoute, podCIDRRoute, serviceCIDRRoute}

	return podIPInfo, nil
}
