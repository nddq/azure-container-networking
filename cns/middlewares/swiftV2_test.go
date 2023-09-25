package middlewares

import (
	"context"
	"os"
	"testing"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/configuration"
	mock "github.com/Azure/azure-container-networking/cns/middlewares/mock"
	"github.com/Azure/azure-container-networking/cns/types"
	"gotest.tools/v3/assert"
)

var (
	testPod1GUID = "898fb8f1-f93e-4c96-9c31-6b89098949a3"
	testPod1Info = cns.NewPodInfo("898fb8-eth0", testPod1GUID, "testpod1", "testpod1namespace")

	testPod2GUID = "b21e1ee1-fb7e-4e6d-8c68-22ee5049944e"
	testPod2Info = cns.NewPodInfo("b21e1e-eth0", testPod2GUID, "testpod2", "testpod2namespace")

	testPod3GUID = "718e04ac-5a13-4dce-84b3-040accaa9b41"
	testPod3Info = cns.NewPodInfo("718e04-eth0", testPod3GUID, "testpod3", "testpod3namespace")
)

func TestValidateMultitenantIPConfigsRequestSuccess(t *testing.T) {
	middleware := SWIFTv2Middleware{Cli: mock.NewMockClient()}

	happyReq := &cns.IPConfigsRequest{
		PodInterfaceID:   testPod1Info.InterfaceID(),
		InfraContainerID: testPod1Info.InfraContainerID(),
	}
	b, _ := testPod1Info.OrchestratorContext()
	happyReq.OrchestratorContext = b
	happyReq.Multitenant = false

	respCode, err := middleware.ValidateMultitenantIPConfigsRequest(happyReq)
	assert.Equal(t, err, "")
	assert.Equal(t, respCode, types.Success)
	assert.Equal(t, happyReq.Multitenant, true)
}

func TestValidateMultitenantIPConfigsRequestFailure(t *testing.T) {
	middleware := SWIFTv2Middleware{Cli: mock.NewMockClient()}

	// Fail to unmarshal pod info test
	failReq := &cns.IPConfigsRequest{
		PodInterfaceID:   testPod1Info.InterfaceID(),
		InfraContainerID: testPod1Info.InfraContainerID(),
	}
	failReq.OrchestratorContext = []byte("invalid")
	respCode, _ := middleware.ValidateMultitenantIPConfigsRequest(failReq)
	assert.Equal(t, respCode, types.UnexpectedError)

	// Pod doesn't exist in cache test
	failReq = &cns.IPConfigsRequest{
		PodInterfaceID:   testPod2Info.InterfaceID(),
		InfraContainerID: testPod2Info.InfraContainerID(),
	}
	b, _ := testPod2Info.OrchestratorContext()
	failReq.OrchestratorContext = b
	respCode, _ = middleware.ValidateMultitenantIPConfigsRequest(failReq)
	assert.Equal(t, respCode, types.UnexpectedError)
}

func TestGetSWIFTv2IPConfigSuccess(t *testing.T) {
	os.Setenv(configuration.EnvPodCIDR, "10.0.1.10/24")
	os.Setenv(configuration.EnvServiceCIDR, "10.0.2.10/24")

	middleware := SWIFTv2Middleware{Cli: mock.NewMockClient()}

	ipInfo, err := middleware.GetSWIFTv2IPConfig(context.TODO(), testPod1Info)
	assert.Equal(t, err, nil)
	assert.Equal(t, ipInfo.NICType, cns.NICTypeSecondary)
	assert.Equal(t, ipInfo.SkipDefaultRoutes, true)
}

func TestGetSWIFTv2IPConfigFailure(t *testing.T) {
	middleware := SWIFTv2Middleware{Cli: mock.NewMockClient()}

	// Pod's MTPNC doesn't exist in cache test
	_, err := middleware.GetSWIFTv2IPConfig(context.TODO(), testPod2Info)
	assert.Error(t, err, "failed to get pod's mtpnc from cache : mtpnc not found")

	// Pod's MTPNC is not ready test
	_, err = middleware.GetSWIFTv2IPConfig(context.TODO(), testPod3Info)
	assert.Error(t, err, ErrMTPNCNotReady.Error())
}
