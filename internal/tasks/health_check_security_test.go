package tasks

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeCommon/pkg/healthcheck"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
)

func TestSecurityHealthProbeDefaultDoesNotMutateSharedConfiguration(t *testing.T) {
	config := &serverconfigs.HealthCheckConfig{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Invalid URL escape rejects before any network call. Concurrent
			// probes must not write their default into the shared cluster config.
			_ = NewHealthCheckExecutor(1).runNodeOnce(config, &HealthCheckResult{NodeAddr: "%"})
		}()
	}
	wg.Wait()
	if config.URL != "" {
		t.Fatal("probe workers mutated their shared cluster configuration")
	}
}

func TestSecurityHealthProbeRequiresTrustedTLSAndDoesNotFollowRedirects(t *testing.T) {
	t.Setenv("EDGE_HEALTHCHECK_CA_FILE", "")
	var leaked atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	var validProbe atomic.Int64
	node := &models.Node{UniqueId: "probe-node", Secret: "0123456789abcdef0123456789abcdef"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, _, err := healthcheck.Verify(req.Header.Get(serverconfigs.HealthCheckHeaderName), node.UniqueId, node.Secret, req); err != nil {
			t.Error(err)
			w.WriteHeader(403)
			return
		}
		validProbe.Add(1)
		http.Redirect(w, req, target.URL, http.StatusFound)
	}))
	defer server.Close()
	executor := NewHealthCheckExecutor(1)
	config := &serverconfigs.HealthCheckConfig{URL: server.URL, StatusCodes: []int{302}, OnlyBasicRequest: true}
	result := &HealthCheckResult{Node: node, NodeAddr: "127.0.0.1"}
	if err := executor.runNodeOnce(config, result); err == nil || result.IsOk {
		t.Fatal("untrusted health probe certificate was accepted")
	}
	ca := filepath.Join(t.TempDir(), "healthcheck-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDGE_HEALTHCHECK_CA_FILE", ca)
	if err := executor.runNodeOnce(config, result); err != nil || !result.IsOk {
		t.Fatalf("trusted signed probe was rejected: %v", err)
	}
	if validProbe.Load() != 1 || leaked.Load() != 0 {
		t.Fatal("probe token was forwarded through a redirect")
	}
}
