package middlewares

import (
	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type MultitenantMiddleware struct {
	// TODO: implement
	// need cached scoped client for pods
	// need client for MTPNC CRD for x-ref pods
	cli client.Client
}

func NewMultitenantMiddleware(cli client.Client) *MultitenantMiddleware {
	return &MultitenantMiddleware{
		cli: cli,
	}
}

// Return the validator function for the middleware
func (m *MultitenantMiddleware) Validator() cns.IPConfigValidator {
	return m.validateMultitenantIPConfigsRequest
}

// validateMultitenantIPConfigsRequest validate whether the request is for a multitenant pod
// nolint
func (m *MultitenantMiddleware) validateMultitenantIPConfigsRequest(ipConfigsRequest *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	/**
	TODO:
	- Check if pod is multitenant, enrich the request with the multitenant flag
	**/
	ipConfigsRequest.Multitenant = true
	return types.Success, ""
}

// nolint
// GetMultitenantIPConfig returns the IP config for a multitenant pod from the MTPNC CRD
func (m *MultitenantMiddleware) GetMultitenantIPConfig(podInfo cns.PodInfo) (*cns.PodIpInfo, error) {
	/**
	TODO:
	- Check if the MTPNC CRD exists for the pod, if not, return error
	**/
	return nil, nil
}
