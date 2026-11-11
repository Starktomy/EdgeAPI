package cryptoutils

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// RandomHex returns exactly size hexadecimal characters. Existing machine
// credential columns are 32 characters, which carry 128 bits of random data.
// Entropy-source failures return no usable credential and are never downgraded
// to timestamps, pseudo-random values or partial output.
func RandomHex(size int) (string, error) {
	return randomHex(size, rand.Reader)
}

func randomHex(size int, source io.Reader) (string, error) {
	if size < 32 || size > 512 || size%2 != 0 {
		return "", errors.New("credential hex length must be an even value between 32 and 512")
	}
	data := make([]byte, size/2)
	if _, err := io.ReadFull(source, data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
