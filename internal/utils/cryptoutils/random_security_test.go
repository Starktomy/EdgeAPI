package cryptoutils

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

type failedEntropy struct{ err error }

func (source failedEntropy) Read([]byte) (int, error) { return 0, source.err }

func TestSecurityMachineCredentialsKeepWireLengthAndIndependentEntropy(t *testing.T) {
	var workers sync.WaitGroup
	values := make(chan string, 512)
	for i := 0; i < cap(values); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			value, err := RandomHex(32)
			if err != nil {
				t.Error(err)
				return
			}
			values <- value
		}()
	}
	workers.Wait()
	close(values)
	seen := make(map[string]bool)
	for value := range values {
		data, err := hex.DecodeString(value)
		if err != nil || len(value) != 32 || len(data) != 16 || value != strings.ToLower(value) || seen[value] {
			t.Fatal("machine credential is not an independent 128-bit value compatible with legacy columns")
		}
		seen[value] = true
	}
	if len(seen) != cap(values) {
		t.Fatal("a credential generation failed without producing an error")
	}
}

func TestSecurityCredentialEntropyFailureNeverReturnsPartialSecret(t *testing.T) {
	failure := errors.New("injected entropy source failure")
	if value, err := randomHex(32, failedEntropy{failure}); !errors.Is(err, failure) || value != "" {
		t.Fatalf("failed entropy produced a usable secret: %q %v", value, err)
	}
	if value, err := randomHex(32, bytes.NewReader([]byte("short"))); !errors.Is(err, io.ErrUnexpectedEOF) || value != "" {
		t.Fatalf("short entropy was padded or downgraded: %q %v", value, err)
	}
	for _, size := range []int{-1, 0, 16, 31, 33, 513} {
		if value, err := RandomHex(size); err == nil || value != "" {
			t.Fatalf("invalid credential length %d accepted", size)
		}
	}
}
