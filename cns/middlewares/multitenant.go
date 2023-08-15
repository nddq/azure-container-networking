package middlewares

import (
	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/types"
)

type IPConfigValidator func(ipConfigsRequest *cns.IPConfigsRequest) (types.ResponseCode, string)

// Middleware interface for testing later on
type Middleware interface {
	Validator() IPConfigValidator
	GetMultitenantIPConfig(podInfo cns.PodInfo) (*cns.PodIpInfo, error)
}

type MultitenantMiddleware struct {
	// TODO: implement
	// need cached scoped client for pods
	// need client for MTPNC CRD for x-ref pods
}

func NewMultitenantMiddleware() *MultitenantMiddleware {
	return &MultitenantMiddleware{}
}

// Return the validator function for the middleware
func (m *MultitenantMiddleware) Validator() IPConfigValidator {
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
