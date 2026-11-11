package passwords

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSecurityAdministratorPasswordLegacyMigration(t *testing.T) {
	const raw = "a-real-password-for-the-test"
	sum := md5.Sum([]byte(raw))
	legacy := hex.EncodeToString(sum[:])
	if ok, replacement, err := VerifyLogin(legacy, RawPrefix+"wrong"); ok || replacement != "" || err != nil {
		t.Fatalf("wrong legacy raw password accepted: %v %q %v", ok, replacement, err)
	}
	if ok, replacement, err := VerifyLogin(legacy, legacy); !ok || replacement != "" || err != nil {
		t.Fatalf("unmigrated legacy client rejected: %v %q %v", ok, replacement, err)
	}
	ok, migrated, err := VerifyLogin(legacy, RawPrefix+raw)
	if !ok || !strings.HasPrefix(migrated, "$argon2id$") || err != nil {
		t.Fatalf("raw legacy login failed to migrate: %v %q %v", ok, migrated, err)
	}
	if ok, replacement, err := VerifyLogin(migrated, RawPrefix+raw); !ok || replacement != "" || err != nil {
		t.Fatalf("migrated raw login failed: %v %q %v", ok, replacement, err)
	}
	for _, supplied := range []string{legacy, raw, "sha256:" + raw, RawPrefix + "wrong"} {
		if ok, _, err := VerifyLogin(migrated, supplied); ok || err != nil {
			t.Fatalf("new hash accepted old hash replay/invalid protocol %q: %v", supplied, err)
		}
	}
}

func TestSecurityAdministratorPasswordHashHasRandomSalt(t *testing.T) {
	a, err := Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("password")
	if err != nil || a == b {
		t.Fatalf("salt must be independently random: %v", err)
	}
	if _, _, _, _, _, err := parse(a); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityAdministratorPasswordRejectsHashParameters(t *testing.T) {
	valid, err := Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{
		strings.Replace(valid, "m=19456", "m=4294967295", 1),
		strings.Replace(valid, "m=19456", "m=0", 1),
		strings.Replace(valid, "t=2", "t=999999", 1),
		strings.Replace(valid, "p=1", "p=0", 1),
		strings.Replace(valid, "v=19", "v=16", 1),
		valid + "$extra",
		"$argon2id$v=19$m=19456,t=2,p=1$bad$bad",
		strings.Repeat("x", 513),
	} {
		if ok, _, err := VerifyLogin(encoded, RawPrefix+"password"); ok || err != nil {
			t.Fatalf("invalid parameters were not rejected: %q, %v", encoded, err)
		}
	}
	if _, err := Hash(""); err == nil {
		t.Fatal("empty password accepted")
	}
	if _, err := Hash(strings.Repeat("x", maxPasswordBytes+1)); err == nil {
		t.Fatal("unbounded password accepted")
	}
}
