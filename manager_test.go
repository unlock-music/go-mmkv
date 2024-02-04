package mmkv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewManager(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		mgr, err := NewManager("./testdata")
		assert.NoError(t, err)
		assert.NotNil(t, mgr)

		vault, err := mgr.OpenVault("")
		assert.NoError(t, err)
		assert.NotNil(t, vault)
	})
	t.Run("Crypto", func(t *testing.T) {
		mgr, err := NewManager("./testdata")
		assert.NoError(t, err)
		assert.NotNil(t, mgr)

		vault, err := mgr.OpenVaultCrypto("crypto", "123456")
		val, err := vault.GetString("world")
		assert.NotNil(t, vault)

		assert.Equal(t, "hello", val)
		assert.NoError(t, err)

		_, err = vault.GetBytes("foo")
		assert.Error(t, err)
	})
}
