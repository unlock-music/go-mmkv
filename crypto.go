package go_mmkv

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

type MMKVCrypto struct {
	src io.Reader

	aesBlock  cipher.Block
	aesStream cipher.Stream
}

func NewMMKVCrypto(src io.Reader, password []byte, iv []byte) (crypto *MMKVCrypto, err error) {
	// aes-128-cfb
	aesBlock, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("iv length must be 16 bytes")
	}

	aesStream := cipher.NewCFBDecrypter(aesBlock, iv)
	crypto = &MMKVCrypto{
		src:       src,
		aesBlock:  aesBlock,
		aesStream: aesStream,
	}
	return crypto, nil
}

func (c *MMKVCrypto) Read(p []byte) (n int, err error) {
	n, err = c.src.Read(p)
	if err != nil {
		return 0, err
	}
	if n != len(p) {
		return n, io.ErrUnexpectedEOF
	}
	c.aesStream.XORKeyStream(p, p)
	return n, nil
}
