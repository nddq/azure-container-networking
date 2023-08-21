package middlewares

import (
	"context"
	"fmt"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/cns/types"
	v1 "k8s.io/api/core/v1"
	k8types "k8s.io/apimachinery/pkg/types"
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

// validateMultitenantIPConfigsRequest validates if pod is multitenant
// nolint
func (m *MultitenantMiddleware) validateMultitenantIPConfigsRequest(req *cns.IPConfigsRequest) (respCode types.ResponseCode, message string) {
	// Retrieve the pod from the cluster
	podInfo, err := cns.UnmarshalPodInfo(req.OrchestratorContext)
	if err != nil {
		errBuf := fmt.Sprintf("unmarshalling pod info from ipconfigs request %v failed with error %v", req, err)
		return types.UnexpectedError, errBuf
	}
	podNamespacedName := k8types.NamespacedName{Namespace: podInfo.Namespace(), Name: podInfo.Name()}
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

// nolint
// GetMultitenantIPConfig returns the IP config for a multitenant pod from the MTPNC CRD
func (m *MultitenantMiddleware) GetMultitenantIPConfig(podInfo cns.PodInfo) (*cns.PodIpInfo, error) {
	/**
	TODO:
	- Check if the MTPNC CRD exists for the pod, if not, return error
	**/
	return nil, nil
}
