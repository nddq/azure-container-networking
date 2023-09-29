package configuration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeName(t *testing.T) {
	_, err := NodeName()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNodeNameUnset)
	os.Setenv(EnvNodeName, "test")
	name, err := NodeName()
	assert.NoError(t, err)
	assert.Equal(t, "test", name)
}

func TestPodCIDRv4(t *testing.T) {
	_, err := PodCIDRv4()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPodCIDRv4Unset)
	os.Setenv(EnvPodCIDRv4, "test")
	cidr, err := PodCIDRv4()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}

func TestServiceCIDR(t *testing.T) {
	_, err := ServiceCIDR()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrServiceCIDRUnset)
	os.Setenv(EnvServiceCIDR, "test")
	cidr, err := ServiceCIDR()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}
