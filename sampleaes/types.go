package sampleaes

import "fmt"

type Config struct {
	Key []byte
	IV  []byte
}

type BlockCryptor interface {
	Reset() error
	CryptBlocks(data []byte) error
}

func (c Config) Validate() error {
	if len(c.Key) != 16 {
		return fmt.Errorf("key must be 16 bytes")
	}
	if len(c.IV) != 16 {
		return fmt.Errorf("iv must be 16 bytes")
	}
	return nil
}
