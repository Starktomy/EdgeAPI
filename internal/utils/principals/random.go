package principals

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// RandomCredential returns URL-safe credentials from the OS random source.
// Size is entropy in bytes, not encoded string length.
func RandomCredential(size int) (string, error) {
	if size < 16 || size > 128 {
		return "", errors.New("invalid credential entropy size")
	}
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
