//go:build !plus

package rpcutils

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/utils/ttlcache"
	"github.com/iwind/TeaGo/dbs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type streamAuthorityFixture struct {
	credentialEnabled bool
	nodeEnabled       bool
	clusterEnabled    bool
	nodeReads         int
}
type streamAuthorityConn struct{ fixture *streamAuthorityFixture }
type streamAuthorityStmt struct {
	fixture *streamAuthorityFixture
	query   string
}
type streamAuthorityRows struct {
	columns []string
	values  []driver.Value
}

var streamAuthorityDriverID atomic.Int64
var streamAuthorityFields = regexp.MustCompile("[`\"]?([a-zA-Z0-9_]+)[`\"]?\\s*=\\s*\\?")

func (f *streamAuthorityFixture) Open(string) (driver.Conn, error) {
	return &streamAuthorityConn{fixture: f}, nil
}
func (*streamAuthorityConn) Close() error { return nil }
func (*streamAuthorityConn) Begin() (driver.Tx, error) {
	return nil, errors.New("stream authorization must not begin a transaction")
}
func (c *streamAuthorityConn) Prepare(query string) (driver.Stmt, error) {
	return &streamAuthorityStmt{fixture: c.fixture, query: query}, nil
}
func (*streamAuthorityStmt) Close() error  { return nil }
func (*streamAuthorityStmt) NumInput() int { return -1 }
func (*streamAuthorityStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("stream authorization must not mutate the database")
}
func (s *streamAuthorityStmt) Query(args []driver.Value) (driver.Rows, error) {
	if strings.Contains(s.query, "@@max_prepared_stmt_count") {
		return &streamAuthorityRows{columns: []string{"max"}, values: []driver.Value{int64(100)}}, nil
	}
	conditions := map[string]driver.Value{}
	for i, match := range streamAuthorityFields.FindAllStringSubmatch(s.query, -1) {
		if i >= len(args) {
			return nil, errors.New("unbound stream authority query")
		}
		conditions[match[1]] = args[i]
	}
	if conditions["state"] != int64(1) {
		return nil, errors.New("stream authority query omitted enabled state")
	}
	switch {
	case strings.Contains(s.query, "edgeApiTokens"):
		if conditions["nodeId"] != "stream-dao-node" {
			return nil, errors.New("credential query omitted authenticated machine")
		}
		rows := &streamAuthorityRows{columns: []string{"nodeId", "secret", "role"}}
		if s.fixture.credentialEnabled {
			rows.values = []driver.Value{"stream-dao-node", "stream-dao-secret-at-least-32-bytes", "node"}
		}
		return rows, nil
	case strings.Contains(s.query, "edgeNodeClusters"):
		if conditions["id"] != int64(10) || conditions["isOn"] != true {
			return nil, errors.New("cluster query omitted enabled primary cluster")
		}
		rows := &streamAuthorityRows{columns: []string{"id"}}
		if s.fixture.clusterEnabled {
			rows.values = []driver.Value{int64(10)}
		}
		return rows, nil
	case strings.Contains(s.query, "edgeNodes"):
		if conditions["uniqueId"] != "stream-dao-node" {
			return nil, errors.New("node query omitted authenticated machine")
		}
		s.fixture.nodeReads++
		rows := &streamAuthorityRows{columns: []string{"id", "clusterId"}}
		if s.fixture.nodeEnabled {
			rows.values = []driver.Value{int64(7), int64(10)}
		}
		return rows, nil
	}
	return nil, errors.New("unexpected stream authority query: " + s.query)
}
func (r *streamAuthorityRows) Columns() []string { return r.columns }
func (*streamAuthorityRows) Close() error        { return nil }
func (r *streamAuthorityRows) Next(dest []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(dest, r.values)
	r.values = nil
	return nil
}

func TestSecurityNodeStreamAuthorityBypassesCachedNodeState(t *testing.T) {
	fixture := &streamAuthorityFixture{credentialEnabled: true, nodeEnabled: true, clusterEnabled: true}
	driverName := "edgeapi-stream-authority-" + strconv.FormatInt(streamAuthorityDriverID.Add(1), 10)
	sql.Register(driverName, fixture)
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: driverName})
	if err != nil {
		t.Fatal(err)
	}
	previousToken, previousNode, previousCluster := models.SharedApiTokenDAO, models.SharedNodeDAO, models.SharedNodeClusterDAO
	models.SharedApiTokenDAO = &models.ApiTokenDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeApiTokens", Model: new(models.ApiToken), PkName: "id"}}
	models.SharedNodeDAO = &models.NodeDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNodes", Model: new(models.Node), PkName: "id"}}
	models.SharedNodeClusterDAO = &models.NodeClusterDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNodeClusters", Model: new(models.NodeCluster), PkName: "id"}}
	t.Cleanup(func() {
		models.SharedApiTokenDAO, models.SharedNodeDAO, models.SharedNodeClusterDAO = previousToken, previousNode, previousCluster
		ttlcache.SharedCache.Delete("nodeId@uniqueId@stream-dao-node")
		_ = db.Close()
	})
	// Simulate another API process having revoked the node while this process
	// still has a previously authenticated ID in the ordinary lookup cache.
	ttlcache.SharedCache.Write("nodeId@uniqueId@stream-dao-node", int64(7), time.Now().Add(time.Minute).Unix())
	ctx := signedRequestContext(t, "stream-dao-node", "stream-dao-secret-at-least-32-bytes", UserTypeNode, 999)
	nodeID, validate, err := NewNodeStreamValidator(ctx)
	if err != nil || nodeID != 7 {
		t.Fatalf("initial authoritative stream handshake: id=%d err=%v", nodeID, err)
	}
	if err := validate(); err != nil || fixture.nodeReads < 2 {
		t.Fatalf("stream validation reused cached state: reads=%d err=%v", fixture.nodeReads, err)
	}
	fixture.nodeEnabled = false
	if err := validate(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("cached enabled node survived database revocation: %v", err)
	}
	fixture.nodeEnabled, fixture.clusterEnabled = true, false
	if err := validate(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream survived primary cluster disablement: %v", err)
	}
	fixture.clusterEnabled, fixture.credentialEnabled = true, false
	if err := validate(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stream survived credential removal: %v", err)
	}
}
