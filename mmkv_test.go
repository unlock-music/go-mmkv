package go_mmkv

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMMKVReader(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		mmkv, err := os.Open("./testdata/mmkv.default")
		assert.NoError(t, err)
		assert.NotNil(t, mmkv)
		defer mmkv.Close()

		r, err := NewMMKVReader(mmkv, nil, nil)
		assert.NoError(t, err)
		assert.NotNil(t, r)

		key1, err := r.ReadKey()
		assert.NoError(t, err)
		assert.Equal(t, "world", key1)
		val1, err := r.ReadStringValue()
		assert.NoError(t, err)
		assert.Equal(t, "hello", val1)

		key2, err := r.ReadKey()
		assert.NoError(t, err)
		assert.Equal(t, "test", key2)
		val2, err := r.ReadStringValue()
		assert.NoError(t, err)
		assert.Equal(t, "unit", val2)
	})

	t.Run("ReadIntValue", func(t *testing.T) {
		mmkv, err := os.Open("./testdata/mmkv_int")
		assert.NoError(t, err)
		assert.NotNil(t, mmkv)
		defer mmkv.Close()

		r, err := NewMMKVReader(mmkv, nil, nil)
		assert.NoError(t, err)
		assert.NotNil(t, r)

		key1, err := r.ReadInt()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0x16e), key1)
		val1, err := r.ReadInt()
		assert.NoError(t, err)
		assert.Equal(t, uint64(0x16c), val1)
	})

	t.Run("Crypto", func(t *testing.T) {
		mmkv, err := os.Open("./testdata/crypto")
		assert.NoError(t, err)
		assert.NotNil(t, mmkv)
		defer mmkv.Close()

		crc, err := os.Open("./testdata/crypto.crc")
		assert.NoError(t, err)
		assert.NotNil(t, crc)
		defer crc.Close()

		r, err := NewMMKVReader(mmkv, []byte("unlock-music:key"), crc)
		assert.NoError(t, err)
		assert.NotNil(t, r)

		key1, err := r.ReadKey()
		assert.NoError(t, err)
		assert.Equal(t, "world", key1)
		val1, err := r.ReadStringValue()
		assert.NoError(t, err)
		assert.Equal(t, "hello", val1)

		key2, err := r.ReadKey()
		assert.NoError(t, err)
		assert.Equal(t, "test", key2)
		val2, err := r.ReadStringValue()
		assert.NoError(t, err)
		assert.Equal(t, "unit", val2)
	})

	t.Run("ToMap", func(t *testing.T) {
		mmkv, err := os.Open("./testdata/mmkv.default")
		assert.NoError(t, err)
		assert.NotNil(t, mmkv)
		defer mmkv.Close()

		m, err := MMKVToMap(mmkv, nil, nil)
		assert.NoError(t, err)
		assert.NotNil(t, m)
		assert.Equal(t, 2, len(m))
		assert.Equal(t, "hello", m["world"])
		assert.Equal(t, "unit", m["test"])
	})
}
