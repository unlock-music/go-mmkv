package mmkv

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/encoding/protowire"
	"unlock-music.dev/mmkv/internal"
)

type vault map[string][]byte

func (v vault) Keys() []string {
	return maps.Keys(v)
}

func (v vault) GetRaw(key string) ([]byte, bool) {
	val, ok := v[key]
	return val, ok
}

func (v vault) GetBytes(key string) ([]byte, error) {
	raw, ok := v[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	val, n := protowire.ConsumeBytes(raw)
	if n < 0 {
		return nil, fmt.Errorf("invalid protobuf bytes")
	}

	return val, nil
}

func (v vault) GetString(key string) (string, error) {
	val, err := v.GetBytes(key)
	if err != nil {
		return "", err
	}
	return string(val), nil
}

// metadata and cryptoKey are optional. but if it exists, validate with them.
func loadVault(src io.Reader, m *metadata, cryptoKey string) (Vault, error) {
	fileSizeBuf := make([]byte, 4)
	_, err := io.ReadFull(src, fileSizeBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read file size: %w", err)
	}
	size := binary.LittleEndian.Uint32(fileSizeBuf)

	if m != nil && size != m.actualSize {
		return nil, fmt.Errorf("metadata and vault payload size mismatch")
	}

	buf := make([]byte, size)
	_, err = io.ReadFull(src, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if m != nil && m.crc32 != crc32.ChecksumIEEE(buf) {
		return nil, fmt.Errorf("metadata and vault payload crc32 mismatch")
	}

	// 将数据库完整解密
	if len(cryptoKey) > 0 {
		m_key := make([]byte, aes.BlockSize) // 16 bytes key
		copy(m_key, cryptoKey)

		block, err := aes.NewCipher(m_key)
		if err != nil {
			return nil, fmt.Errorf("failed to create aes cipher")
		}
		stream := cipher.NewCFBDecrypter(block, m.aesVector)
		stream.XORKeyStream(buf, buf)
	}

	v := make(vault)

	// mmkv is not really protobuf compatible,
	// type of key & value (the first 4 bytes) is incorrect.
	// so skip the first 4 bytes & manually parse the rest.
	rd := internal.NewProtoBuffer(buf[4:])

	for {
		if len(rd.Unread()) == 0 {
			break
		}

		key, err := rd.DecodeStringBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to decode key: %w", err)
		}
		val, err := rd.DecodeRawBytes(false)
		if err != nil {
			return nil, fmt.Errorf("failed to decode value: %w", err)
		}
		v[key] = val

	}

	return v, nil
}
