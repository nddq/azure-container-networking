package cniconflist

import (
	"encoding/json"

	"github.com/Azure/azure-container-networking/cni"
	"github.com/Azure/azure-container-networking/cni/util"
	"github.com/Azure/azure-container-networking/network"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/pkg/errors"
)

var errNotImplemented = errors.New("cni conflist generator not implemented on Windows")

// V4Overlay N/A for Windows
func (v *V4OverlayGenerator) Generate() error {
	return errNotImplemented
}

// DualStackOverlay N/A for Windows
func (v *DualStackOverlayGenerator) Generate() error {
	return errNotImplemented
}

func (v *OverlayGenerator) Generate() error {
	conflist := cniConflist{
		CNIVersion:  overlaycniVersion,
		Name:        overlaycniName,
		AdapterName: "",
		Plugins: []any{
			cni.NetworkConfig{
				Type:         overlaycniType,
				Mode:         "bridge",
				Bridge:       "azure0",
				Capabilities: map[string]bool{"portMappings": true, "dns": true},
				IPAM: cni.IPAM{
					Type: network.AzureCNS,
					Mode: string(util.V4Overlay),
				},
				DNS: cniTypes.DNS{
					Nameservers: []string{"10.0.0.10", "168.63.129.16"},
					Search:      []string{"svc.cluster.local"},
				},
				AdditionalArgs: []cni.KVPair{
					{
						Name: "EndpointPolicy",
						Value: json.RawMessage(`{
							"Type": "OutBoundNAT",
                        	"ExceptionList": [
                            	"10.240.0.0/16",
                            	"10.0.0.0/8"
                        	]
						}`),
					},
					{
						Name: "EndpointPolicy",
						Value: json.RawMessage(`{
							"Type": "ROUTE",
							"DestinationPrefix": "10.0.0.0/8",
                        	"NeedEncap": true
						}`),
					},
				},
			},
		},
	}
	enc := json.NewEncoder(v.Writer)
	enc.SetIndent("", "\t")
	if err := enc.Encode(conflist); err != nil {
		return errors.Wrap(err, "error encoding conflist to json")
	}
	return nil
}

// Cilium N/A for Windows
func (v *CiliumGenerator) Generate() error {
	return errNotImplemented
}

func (v *SWIFTGenerator) Generate() error {
	conflist := cniConflist{
		CNIVersion:  azurecniVersion,
		Name:        azureName,
		AdapterName: "",
		Plugins: []any{
			cni.NetworkConfig{
				Type:          overlaycniType,
				Mode:          "bridge",
				Bridge:        "azure0",
				ExecutionMode: string(util.V4Swift),
				Capabilities:  map[string]bool{"portMappings": true, "dns": true},
				IPAM: cni.IPAM{
					Type: network.AzureCNS,
				},
				DNS: cniTypes.DNS{
					Nameservers: []string{"10.0.0.10", "168.63.129.16"},
					Search:      []string{"svc.cluster.local"},
				},
				AdditionalArgs: []cni.KVPair{
					{
						Name: "EndpointPolicy",
						Value: []byte(`{
							"Type": "OutBoundNAT",
                        	"ExceptionList": [
                            	"10.240.0.0/16",
                            	"10.0.0.0/8"
                        	]
						}`),
					},
					{
						Name: "EndpointPolicy",
						Value: []byte(`{
							"Type": "ROUTE",
							"DestinationPrefix": "10.0.0.0/8",
                        	"NeedEncap": true
						}`),
					},
				},
				WindowsSettings: cni.WindowsSettings{
					HnsTimeoutDurationInSeconds: 120,
				},
			},
		},
	}
	enc := json.NewEncoder(v.Writer)
	enc.SetIndent("", "\t")
	if err := enc.Encode(conflist); err != nil {
		return errors.Wrap(err, "error encoding conflist to json")
	}
	return nil
}
