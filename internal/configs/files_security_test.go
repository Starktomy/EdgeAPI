package configs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iwind/TeaGo/Tea"
)

func assertPrivateConfiguration(t *testing.T, path string) {
	t.Helper()
	for filename, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(filename)
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != mode {
			t.Fatalf("credential path %s has unsafe mode or is missing: %v %v", filename, info, err)
		}
	}
}

func TestSecurityAPIConfigurationAndBackupsRemainPrivate(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "configs", "api.yaml")
	backup := filepath.Join(dir, "backup")
	data := []byte("nodeId: fixture-node\nsecret: fixture-secret\n")
	if err := writeAPIConfigFiles(filename, data, []string{backup}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filename, filepath.Join(backup, "api.yaml")} {
		assertPrivateConfiguration(t, path)
		if stored, err := os.ReadFile(path); err != nil || string(stored) != string(data) {
			t.Fatal("private configuration does not contain the requested credentials", err)
		}
	}
}

func TestSecurityAPIFallbackRestoresCredentialsWithPrivateModes(t *testing.T) {
	previousConfigDir := Tea.ConfigDir()
	Tea.SetConfigDir(filepath.Join(t.TempDir(), "configs"))
	t.Cleanup(func() { Tea.SetConfigDir(previousConfigDir) })
	previousShared := sharedAPIConfig
	sharedAPIConfig = nil
	t.Cleanup(func() { sharedAPIConfig = previousShared })
	home := t.TempDir()
	t.Setenv("HOME", home)
	backup := filepath.Join(home, ".edge-api")
	if err := os.MkdirAll(backup, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"api.yaml": "nodeId: fallback-node\nsecret: fallback-secret\n", "db.yaml": "database: fixture\npassword: fallback-database-secret\n"} {
		if err := os.WriteFile(filepath.Join(backup, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := SharedAPIConfig()
	if err != nil || config.NodeId != "fallback-node" || config.Secret != "fallback-secret" {
		t.Fatalf("valid fallback credentials were not restored: %v", err)
	}
	assertPrivateConfiguration(t, Tea.ConfigFile("api.yaml"))
	assertPrivateConfiguration(t, Tea.ConfigFile("db.yaml"))
}

func TestSecurityGeneratedDatabaseConfigurationIsPrivate(t *testing.T) {
	previousConfigDir := Tea.ConfigDir()
	Tea.SetConfigDir(filepath.Join(t.TempDir(), "configs"))
	t.Cleanup(func() { Tea.SetConfigDir(previousConfigDir) })
	config := &SimpleDBConfig{User: "fixture", Password: "fixture-secret", Host: "127.0.0.1:3306", Database: "fixture"}
	if err := config.GenerateOldConfig(); err != nil {
		t.Fatal(err)
	}
	assertPrivateConfiguration(t, Tea.ConfigFile(".db.yaml"))
}
