package middlewares

import (
	"context"
	"errors"

	"github.com/Azure/azure-container-networking/cns/configuration"
	"github.com/Azure/azure-container-networking/crd/multitenancy/api/v1alpha1"
	"github.com/Azure/azure-container-networking/crd/nodenetworkconfig/api/v1alpha"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errPodNotFound   = errors.New("pod not found")
	errMTPNCNotFound = errors.New("mtpnc not found")
	errNNCNotFound   = errors.New("nnc not found")
)

// MockClient implements the client.Client interface for testing. We only care about Get.
type MockClient struct {
	mtPodCache map[string]*v1.Pod
	mtpncCache map[string]*v1alpha1.MultitenantPodNetworkConfig
	nncCache   map[string]*v1alpha.NodeNetworkConfig
}

// NewMockClient returns a new MockClient.
func NewMockClient() *MockClient {
	testPod1 := v1.Pod{}
	testPod1.Labels = make(map[string]string)
	testPod1.Labels[configuration.LabelSwiftV2] = "true"

	testMTPNC1 := v1alpha1.MultitenantPodNetworkConfig{}
	testMTPNC1.Status.PrimaryIP = "192.168.0.1"
	testMTPNC1.Status.MacAddress = "00:00:00:00:00:00"
	testMTPNC1.Status.GatewayIP = "10.0.0.1"
	testMTPNC1.Status.NCID = "testncid"

	testMTPNC3 := v1alpha1.MultitenantPodNetworkConfig{}

	testNNC := v1alpha.NodeNetworkConfig{
		Status: v1alpha.NodeNetworkConfigStatus{
			NetworkContainers: []v1alpha.NetworkContainer{
				{
					DefaultGateway: "1.1.1.1",
				},
			},
		},
	}
	return &MockClient{
		mtPodCache: map[string]*v1.Pod{"testpod1namespace/testpod1": &testPod1},
		mtpncCache: map[string]*v1alpha1.MultitenantPodNetworkConfig{
			"testpod1namespace/testpod1": &testMTPNC1,
			"testpod3namespace/testpod3": &testMTPNC3,
		},
		nncCache: map[string]*v1alpha.NodeNetworkConfig{"kube-system/testnode": &testNNC},
	}
}

// Get implements client.Client.Get.
func (c *MockClient) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	switch o := obj.(type) {
	case *v1.Pod:
		if pod, ok := c.mtPodCache[key.String()]; ok {
			*o = *pod
		} else {
			return errPodNotFound
		}
	case *v1alpha1.MultitenantPodNetworkConfig:
		if mtpnc, ok := c.mtpncCache[key.String()]; ok {
			*o = *mtpnc
		} else {
			return errMTPNCNotFound
		}
	case *v1alpha.NodeNetworkConfig:
		if nnc, ok := c.nncCache[key.String()]; ok {
			*o = *nnc
		} else {
			return errNNCNotFound
		}
	}
	return nil
}

// List implements client.Client.List.
func (c *MockClient) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return nil
}

// Create implements client.Client.Create.
func (c *MockClient) Create(_ context.Context, _ client.Object, _ ...client.CreateOption) error {
	return nil
}

// Delete implements client.Client.Delete.
func (c *MockClient) Delete(_ context.Context, _ client.Object, _ ...client.DeleteOption) error {
	return nil
}

// Update implements client.Client.Update.
func (c *MockClient) Update(_ context.Context, _ client.Object, _ ...client.UpdateOption) error {
	return nil
}

// Patch implements client.Client.Patch.
func (c *MockClient) Patch(_ context.Context, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
	return nil
}

// DeleteAllOf implements client.Client.DeleteAllOf.
func (c *MockClient) DeleteAllOf(_ context.Context, _ client.Object, _ ...client.DeleteAllOfOption) error {
	return nil
}

// Status implements client.StatusClient.
func (c *MockClient) Status() client.StatusWriter {
	return nil
}

// RESTMapper implements client.Client.
func (c *MockClient) RESTMapper() meta.RESTMapper {
	return nil
}

// Scheme implements client.Client.
func (c *MockClient) Scheme() *runtime.Scheme {
	return nil
}

// GroupVersionKindFor implements client.Client.
func (c *MockClient) GroupVersionKindFor(_ runtime.Object) (schema.GroupVersionKind, error) {
	return schema.GroupVersionKind{}, nil
}

// IsObjectNamespaced implements client.Client.
func (c *MockClient) IsObjectNamespaced(_ runtime.Object) (bool, error) {
	return false, nil
}

// SubResource implements client.Client.
func (c *MockClient) SubResource(_ string) client.SubResourceClient {
	return nil
}
