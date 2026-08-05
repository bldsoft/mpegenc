package sampleaes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type CBCEncryptor struct {
	block  cipher.Block
	initIV [aes.BlockSize]byte
	mode   cipher.BlockMode
}

func NewCBCEncryptor(cfg Config) *CBCEncryptor {
	block, _ := aes.NewCipher(cfg.Key)
	return &CBCEncryptor{
		block:  block,
		initIV: [16]byte(cfg.IV),
	}
}

func (e *CBCEncryptor) Reset() error {
	e.mode = cipher.NewCBCEncrypter(e.block, e.initIV[:])
	return nil
}

func (e *CBCEncryptor) CryptBlocks(data []byte) error {
	if len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("data length %d must be a multiple of the block size", len(data))
	}
	e.mode.CryptBlocks(data, data)
	return nil
}
