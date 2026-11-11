package setup

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

func TestSecurityInitialAPIBindsConfiguredLoopbackAddress(t *testing.T) {
	t.Setenv("EDGE_ALLOW_PLAINTEXT_RPC", "")
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "true")
	for _, host := range []string{"127.0.0.1", "::1"} {
		listen, err := setupListenAddress(&Config{APINodeProtocol: "http", APINodeHost: host, APINodePort: 8003})
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the exact JSON format consumed by APINode.DecodeHTTP.
		encoded, err := json.Marshal(&serverconfigs.HTTPProtocolConfig{IsOn: true, Listen: []*serverconfigs.NetworkAddressConfig{listen}})
		if err != nil {
			t.Fatal(err)
		}
		var decoded serverconfigs.HTTPProtocolConfig
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := decoded.Listen[0].Init(); err != nil {
			t.Fatal(err)
		}
		addresses := decoded.Listen[0].Addresses()
		if len(addresses) != 1 || addresses[0] != net.JoinHostPort(host, "8003") || !rpcauth.PlaintextAllowed(addresses[0]) {
			t.Fatalf("installed loopback API became a wildcard or unreachable endpoint: %v", addresses)
		}
	}
}

func TestSecurityInitialAPIRejectsExternalPlaintextBeforeDatabaseAccess(t *testing.T) {
	t.Setenv("EDGE_ALLOW_PLAINTEXT_RPC", "")
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "true")
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.1", "localhost", "api.example.test"} {
		// No database is configured. These must be rejected before setup can
		// create database records or publish a non-loopback plaintext endpoint.
		if err := NewSetup(&Config{APINodeProtocol: "http", APINodeHost: host, APINodePort: 8003}).Run(); err == nil || !strings.Contains(err.Error(), "plaintext API installation") {
			t.Fatalf("plaintext endpoint %q was not rejected before database access: %v", host, err)
		}
	}
	t.Setenv("EDGE_ALLOW_LOOPBACK_RPC", "")
	if _, err := setupListenAddress(&Config{APINodeProtocol: "http", APINodeHost: "127.0.0.1", APINodePort: 8003}); err == nil {
		t.Fatal("plaintext initial installation did not require an operator decision")
	}
	listen, err := setupListenAddress(&Config{APINodeProtocol: "https", APINodeHost: "192.0.2.1", APINodePort: 8003})
	if err != nil || listen.Host != "192.0.2.1" {
		t.Fatalf("verified TLS installation lost its explicit bind address: %v", err)
	}
}
