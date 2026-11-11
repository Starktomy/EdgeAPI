// Package passwords stores administrator passwords and supports the explicit
// raw-v1 login protocol while existing MD5 records are migrated on login.
package passwords

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	RawPrefix               = "raw-v1:"
	maxPasswordBytes        = 4096
	defaultMemory    uint32 = 19 * 1024
	defaultTime      uint32 = 2
	defaultThreads   uint8  = 1
)

// Bound concurrent KDF work even when callers race multiple login requests.
var kdfSlots = make(chan struct{}, 4)

func Hash(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxPasswordBytes {
		return "", errors.New("invalid administrator password length")
	}
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	key, err := derive(raw, salt[:], defaultMemory, defaultTime, defaultThreads, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", defaultMemory, defaultTime, defaultThreads,
		base64.RawStdEncoding.EncodeToString(salt[:]), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyLogin never interprets an unprefixed legacy digest as a raw password.
// A successful raw-v1 check against a legacy record returns a replacement hash
// which the caller must persist with compare-and-swap before accepting login.
func VerifyLogin(stored string, supplied string) (ok bool, replacement string, err error) {
	if len(stored) > 512 || len(supplied) > maxPasswordBytes+len(RawPrefix) {
		return false, "", nil
	}
	if !strings.HasPrefix(supplied, RawPrefix) {
		if !legacyMD5(stored) || !legacyMD5(supplied) {
			return false, "", nil
		}
		return subtle.ConstantTimeCompare([]byte(stored), []byte(supplied)) == 1, "", nil
	}
	raw := strings.TrimPrefix(supplied, RawPrefix)
	if len(raw) == 0 || len(raw) > maxPasswordBytes {
		return false, "", nil
	}
	if legacyMD5(stored) {
		sum := md5.Sum([]byte(raw))
		candidate := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) != 1 {
			return false, "", nil
		}
		replacement, err = Hash(raw)
		return err == nil, replacement, err
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		return false, "", nil
	}
	memory, iterations, threads, salt, key, err := parse(stored)
	if err != nil {
		return false, "", nil
	}
	candidate, err := derive(raw, salt, memory, iterations, threads, uint32(len(key)))
	if err != nil {
		return false, "", err
	}
	return subtle.ConstantTimeCompare(candidate, key) == 1, "", nil
}

func derive(raw string, salt []byte, memory uint32, iterations uint32, threads uint8, length uint32) ([]byte, error) {
	select {
	case kdfSlots <- struct{}{}:
		defer func() { <-kdfSlots }()
	default:
		return nil, errors.New("administrator password verification is busy")
	}
	return argon2.IDKey([]byte(raw), salt, iterations, memory, threads, length), nil
}

func legacyMD5(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func parse(encoded string) (memory uint32, iterations uint32, threads uint8, salt []byte, key []byte, err error) {
	invalid := errors.New("invalid administrator password hash")
	parts := strings.Split(encoded, "$")
	if len(encoded) > 512 || len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return 0, 0, 0, nil, nil, invalid
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return 0, 0, 0, nil, nil, invalid
	}
	readParameter := func(value string, prefix string, bits int) (uint64, error) {
		if !strings.HasPrefix(value, prefix) {
			return 0, invalid
		}
		digits := strings.TrimPrefix(value, prefix)
		if digits == "" || (len(digits) > 1 && digits[0] == '0') {
			return 0, invalid
		}
		for _, c := range digits {
			if c < '0' || c > '9' {
				return 0, invalid
			}
		}
		return strconv.ParseUint(digits, 10, bits)
	}
	m, e1 := readParameter(parameters[0], "m=", 32)
	ti, e2 := readParameter(parameters[1], "t=", 32)
	p, e3 := readParameter(parameters[2], "p=", 8)
	// The supported range prevents corrupted or hostile database parameters from
	// allocating arbitrary memory or launching unbounded Argon2 work.
	if e1 != nil || e2 != nil || e3 != nil || m < uint64(defaultMemory) || m > 64*1024 || ti < 2 || ti > 4 || p < 1 || p > 4 {
		return 0, 0, 0, nil, nil, invalid
	}
	salt, e1 = base64.RawStdEncoding.Strict().DecodeString(parts[4])
	key, e2 = base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if e1 != nil || e2 != nil || len(salt) < 16 || len(salt) > 32 || len(key) != 32 || strings.ContainsAny(parts[4]+parts[5], "\r\n") {
		return 0, 0, 0, nil, nil, invalid
	}
	return uint32(m), uint32(ti), uint8(p), salt, key, nil
}
