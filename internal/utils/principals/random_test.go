package principals

import (
	"encoding/base64"
	"testing"
)

func TestSecurityRandomCredentials(t *testing.T) {
	seen := make(map[string]bool)
	for _, size := range []int{16, 32, 96} {
		for i := 0; i < 32; i++ {
			value, err := RandomCredential(size)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil || len(decoded) != size || seen[value] {
				t.Fatal("invalid or repeated credential")
			}
			seen[value] = true
		}
	}
	for _, size := range []int{-1, 0, 8, 129} {
		if _, err := RandomCredential(size); err == nil {
			t.Fatal("invalid credential size accepted")
		}
	}
}
