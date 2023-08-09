package middlewares

import (
	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/types"
)

type MultitenantValidator struct {
	// TODO: implement
	// need cached scoped client for pods
}

func NewMultitenantValidator() *MultitenantValidator {
	return &MultitenantValidator{}
}

// validateMultitenantIPConfigsRequest validate whether the request is for a multitenant pod
// nolint
func (v *MultitenantValidator) validateMultitenantIPConfigsRequest(ipConfigsRequest *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	// TODO: if pod is multitenant, enrich the request with the multitenant flag
	ipConfigsRequest.Multitenant = true
	return types.Success, ""
}
