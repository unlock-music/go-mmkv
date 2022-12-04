package mmkv

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_loadVault(t *testing.T) {
	file, err := os.Open("./testdata/mmkv.default")
	require.NoError(t, err)

	v, err := loadVault(file, nil)
	require.NoError(t, err)

	assert.Equal(t, 2, len(v.Keys()))

	val, ok := v.Get("world")
	assert.Equal(t, "hello", string(val))
	assert.True(t, ok)

	val, ok = v.Get("foo")
	assert.False(t, ok)
}
