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

func TestPodV4CIDR(t *testing.T) {
	_, err := PodV4CIDRs()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPodV4CIDRsUnset)
	os.Setenv(EnvPodV4CIDRs, "test")
	cidr, err := PodV4CIDRs()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}

func TestPodV6CIDR(t *testing.T) {
	_, err := PodV6CIDRs()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPodV6CIDRsUnset)
	os.Setenv(EnvPodV6CIDRs, "test")
	cidr, err := PodV6CIDRs()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}

func TestServiceV4CIDR(t *testing.T) {
	_, err := ServiceV4CIDR()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrServiceV4CIDRUnset)
	os.Setenv(EnvServiceV4CIDR, "test")
	cidr, err := ServiceV4CIDR()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}

func TestServiceV6CIDR(t *testing.T) {
	_, err := ServiceV6CIDR()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrServiceV6CIDRUnset)
	os.Setenv(EnvServiceV6CIDR, "test")
	cidr, err := ServiceV6CIDR()
	assert.NoError(t, err)
	assert.Equal(t, "test", cidr)
}
