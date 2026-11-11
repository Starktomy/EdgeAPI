package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestSecurityInstallerRequiresDatabasePasswordAndRedactsVerboseLogs(t *testing.T) {
	for _, environment := range []map[string]string{{}, {"EDGE_DB_PASSWORD": ""}} {
		if _, err := databaseSettingsFromEnv(func(name string) (string, bool) { value, exists := environment[name]; return value, exists }); err == nil {
			t.Fatal("installer retained a default or empty database password")
		}
	}
	const password = " secret-marker-安装:@/ whitespace "
	environment := map[string]string{"EDGE_DB_PASSWORD": password, "EDGE_DB_HOST": "192.0.2.4", "EDGE_DB_NAME": "explicit_edges"}
	config, err := databaseSettingsFromEnv(func(name string) (string, bool) { value, exists := environment[name]; return value, exists })
	if err != nil || config.Password != password || config.Host != "192.0.2.4" || config.Name != "explicit_edges" {
		t.Fatalf("explicit database settings changed: %v", err)
	}
	var output bytes.Buffer
	config.log(log.New(&output, "", 0))
	if strings.Contains(output.String(), "secret-marker") || !strings.Contains(output.String(), "EDGE_DB_PASSWORD=[redacted]") {
		t.Fatal("verbose mode exposed a database password")
	}
}
