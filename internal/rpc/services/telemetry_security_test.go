package services

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/iwind/TeaGo/dbs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type telemetryFixtureDriver struct{}
type telemetryFixtureConn struct{}
type telemetryFixtureStmt struct{ query string }
type telemetryFixtureRows struct {
	columns []string
	values  []driver.Value
}

var telemetryFixtureID atomic.Int64

func (*telemetryFixtureDriver) Open(string) (driver.Conn, error) {
	return &telemetryFixtureConn{}, nil
}
func (*telemetryFixtureConn) Close() error { return nil }
func (*telemetryFixtureConn) Begin() (driver.Tx, error) {
	return nil, errors.New("this read-only authorization fixture does not allow transactions")
}
func (*telemetryFixtureConn) Prepare(query string) (driver.Stmt, error) {
	return &telemetryFixtureStmt{query: query}, nil
}
func (*telemetryFixtureStmt) Close() error  { return nil }
func (*telemetryFixtureStmt) NumInput() int { return -1 }
func (*telemetryFixtureStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("authorization performed an unexpected storage mutation")
}
func (s *telemetryFixtureStmt) Query(args []driver.Value) (driver.Rows, error) {
	if strings.Contains(s.query, "@@max_prepared_stmt_count") {
		return &telemetryFixtureRows{columns: []string{"max"}, values: []driver.Value{int64(100)}}, nil
	}
	if len(args) == 0 {
		return nil, errors.New("authorization query has no bound identity")
	}
	id, ok := args[0].(int64)
	if !ok {
		return nil, errors.New("authorization query identity is not an integer")
	}
	switch {
	case strings.Contains(s.query, "edgeNSNodes"):
		rows := &telemetryFixtureRows{columns: []string{"clusterId"}}
		if id == 70 {
			rows.values = []driver.Value{int64(10)}
		}
		return rows, nil
	case strings.Contains(s.query, "edgeNodes"):
		rows := &telemetryFixtureRows{columns: []string{"id", "regionId", "clusterId", "secondaryClusterIds"}}
		if id == 7 {
			rows.values = []driver.Value{int64(7), int64(3), int64(10), []byte("[20]")}
		}
		return rows, nil
	case strings.Contains(s.query, "edgeServers"):
		rows := &telemetryFixtureRows{columns: []string{"id", "clusterId", "userId", "userPlanId", "lastUserPlanId"}}
		switch id {
		case 101:
			rows.values = []driver.Value{id, int64(10), int64(42), int64(501), int64(500)}
		case 102:
			rows.values = []driver.Value{id, int64(20), int64(43), int64(0), int64(0)}
		case 103:
			rows.values = []driver.Value{id, int64(30), int64(44), int64(0), int64(0)}
		case 104:
			rows.values = []driver.Value{id, int64(10), int64(42), int64(502), int64(502)}
		}
		return rows, nil
	case strings.Contains(s.query, "edgeUserPlans"):
		rows := &telemetryFixtureRows{columns: []string{"id", "userId", "planId", "state"}}
		switch id {
		case 500:
			// Deleted plans remain valid historical billing references.
			rows.values = []driver.Value{id, int64(42), int64(8), int64(0)}
		case 501:
			rows.values = []driver.Value{id, int64(42), int64(9), int64(1)}
		case 502:
			// A corrupt/stale server reference cannot charge another user.
			rows.values = []driver.Value{id, int64(99), int64(10), int64(1)}
		}
		return rows, nil
	}
	return nil, errors.New("unexpected authorization table: " + s.query)
}
func (r *telemetryFixtureRows) Columns() []string { return r.columns }
func (*telemetryFixtureRows) Close() error        { return nil }
func (r *telemetryFixtureRows) Next(dest []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(dest, r.values)
	r.values = nil
	return nil
}

func installTelemetryFixture(t *testing.T) {
	t.Helper()
	name := "edgeapi-telemetry-security-" + strconv.FormatInt(telemetryFixtureID.Add(1), 10)
	sql.Register(name, &telemetryFixtureDriver{})
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: name})
	if err != nil {
		t.Fatal(err)
	}
	previousNode, previousNS, previousServer, previousPlan := models.SharedNodeDAO, models.SharedNSNodeDAO, models.SharedServerDAO, models.SharedUserPlanDAO
	models.SharedNodeDAO = &models.NodeDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNodes", Model: new(models.Node), PkName: "id"}}
	models.SharedNSNodeDAO = &models.NSNodeDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeNSNodes", Model: new(models.NSNode), PkName: "id"}}
	models.SharedServerDAO = &models.ServerDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeServers", Model: new(models.Server), PkName: "id"}}
	models.SharedUserPlanDAO = &models.UserPlanDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeUserPlans", Model: new(models.UserPlan), PkName: "id"}}
	t.Cleanup(func() {
		models.SharedNodeDAO, models.SharedNSNodeDAO, models.SharedServerDAO, models.SharedUserPlanDAO = previousNode, previousNS, previousServer, previousPlan
		_ = db.Close()
	})
}

func TestSecurityTrafficUploadShape(t *testing.T) {
	now := time.Unix(1800000000, 0)
	valid := &pb.UploadServerDailyStatsRequest{
		Stats:       []*pb.ServerDailyStat{{ServerId: 101, CreatedAt: now.Unix(), Bytes: 100, CachedBytes: 20, CountRequests: 10, CountCachedRequests: 2, CountAttackRequests: 1}},
		DomainStats: []*pb.UploadServerDailyStatsRequest_DomainStat{{ServerId: 101, Domain: "example.test", CreatedAt: now.Unix()}},
	}
	if err := validateTrafficUpload(valid, now); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}
	if err := validateTrafficUpload(nil, now); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil upload: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*pb.UploadServerDailyStatsRequest)
	}{
		{"nil server record", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0] = nil }},
		{"nil domain record", func(r *pb.UploadServerDailyStatsRequest) { r.DomainStats[0] = nil }},
		{"negative bytes", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].Bytes = -1 }},
		{"cache exceeds total", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].CachedBytes = 101 }},
		{"cache requests exceed total", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].CountCachedRequests = 11 }},
		{"attacks exceed total", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].CountAttackRequests = 11 }},
		{"negative owner", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].UserId = -1 }},
		{"negative plan", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].PlanId = -1 }},
		{"far future", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].CreatedAt = now.Unix() + 301 }},
		{"before supported epoch", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].CreatedAt = 1577836799 }},
		{"numeric overflow allowance", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].Bytes = 1<<46 + 1 }},
		{"domain negative bytes", func(r *pb.UploadServerDailyStatsRequest) { r.DomainStats[0].Bytes = -1 }},
		{"domain control character", func(r *pb.UploadServerDailyStatsRequest) { r.DomainStats[0].Domain = "example.test\nforged" }},
		{"domain too long", func(r *pb.UploadServerDailyStatsRequest) { r.DomainStats[0].Domain = strings.Repeat("a", 254) }},
		{"mixed batch too large", func(r *pb.UploadServerDailyStatsRequest) { r.Stats = make([]*pb.ServerDailyStat, 2000) }},
		{"wire size too large", func(r *pb.UploadServerDailyStatsRequest) { r.Stats[0].Day = strings.Repeat("x", 4<<20) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := proto.Clone(valid).(*pb.UploadServerDailyStatsRequest)
			test.mutate(req)
			if err := validateTrafficUpload(req, now); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("invalid upload accepted: %v", err)
			}
		})
	}
}

func TestSecurityTrafficScopeAndHistoricalPlans(t *testing.T) {
	installTelemetryFixture(t)
	input := &pb.UploadServerDailyStatsRequest{
		Stats: []*pb.ServerDailyStat{
			{ServerId: 101, PlanId: 8, NodeRegionId: 999}, // Historical plan.
			{ServerId: 102, UserId: 43, NodeRegionId: 999},
		},
		DomainStats: []*pb.UploadServerDailyStatsRequest_DomainStat{{ServerId: 102, Domain: "example.test"}},
	}
	wire, err := (proto.MarshalOptions{Deterministic: true}).Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	output, clusters, err := authorizeTrafficUpload(nil, rpcutils.UserTypeNode, 7, input)
	if err != nil {
		t.Fatal(err)
	}
	if clusters[101] != 10 || clusters[102] != 20 || output.Stats[0].PlanId != 8 {
		t.Fatal("primary/secondary clusters or historical plan were not preserved")
	}
	if output.Stats[0].UserId != 42 || output.Stats[0].NodeRegionId != 3 || !output.Stats[0].CheckTrafficLimiting || output.Stats[1].NodeRegionId != 3 {
		t.Fatal("storage fields were not derived from the authenticated node and server")
	}
	after, err := (proto.MarshalOptions{Deterministic: true}).Marshal(input)
	if err != nil || !bytes.Equal(wire, after) {
		t.Fatal("normalization changed the wire payload used for retry receipt hashing")
	}
	for _, test := range []struct {
		name string
		stat *pb.ServerDailyStat
	}{
		{"outside cluster", &pb.ServerDailyStat{ServerId: 103}},
		{"missing server", &pb.ServerDailyStat{ServerId: 999}},
		{"anonymous HTTP service", &pb.ServerDailyStat{ServerId: 0}},
		{"forged tenant", &pb.ServerDailyStat{ServerId: 101, UserId: 99, PlanId: 9}},
		{"unretained plan", &pb.ServerDailyStat{ServerId: 101, PlanId: 7}},
		{"unassigned plan forbidden", &pb.ServerDailyStat{ServerId: 101, PlanId: 0}},
		{"other tenant's plan", &pb.ServerDailyStat{ServerId: 104, PlanId: 10}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A good first record must not allow a later forbidden record through.
			request := &pb.UploadServerDailyStatsRequest{Stats: []*pb.ServerDailyStat{{ServerId: 101, PlanId: 9}, test.stat}}
			result, _, err := authorizeTrafficUpload(nil, rpcutils.UserTypeNode, 7, request)
			if status.Code(err) != codes.PermissionDenied || result != nil {
				t.Fatalf("unauthorized statistics batch accepted: %v", err)
			}
		})
	}
	if _, _, err := authorizeTrafficUpload(nil, rpcutils.UserTypeNode, 999, input); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing node accepted: %v", err)
	}
	if _, _, err := authorizeTrafficUpload(nil, rpcutils.UserTypeNode, 7, &pb.UploadServerDailyStatsRequest{DomainStats: []*pb.UploadServerDailyStatsRequest_DomainStat{{ServerId: 103}}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-cluster domain statistics accepted: %v", err)
	}
}

func TestSecurityDNSTrafficScope(t *testing.T) {
	installTelemetryFixture(t)
	legacy := &pb.UploadServerDailyStatsRequest{Stats: []*pb.ServerDailyStat{{ServerId: 0, NodeRegionId: 999, CheckTrafficLimiting: true}}}
	output, clusters, err := authorizeTrafficUpload(nil, rpcutils.UserTypeDNS, 70, legacy)
	if err != nil {
		t.Fatalf("legacy anonymous DNS statistics rejected: %v", err)
	}
	if clusters[0] != 10 || output.Stats[0].NodeRegionId != 0 || output.Stats[0].CheckTrafficLimiting {
		t.Fatal("DNS statistics could choose a region or affect HTTP quota enforcement")
	}
	if legacy.Stats[0].NodeRegionId != 999 || !legacy.Stats[0].CheckTrafficLimiting {
		t.Fatal("DNS normalization mutated the sender's original payload")
	}
	for _, input := range []*pb.UploadServerDailyStatsRequest{
		{Stats: []*pb.ServerDailyStat{{ServerId: 101}}},
		{Stats: []*pb.ServerDailyStat{{UserId: 42}}},
		{Stats: []*pb.ServerDailyStat{{PlanId: 9}}},
		{DomainStats: []*pb.UploadServerDailyStatsRequest_DomainStat{{ServerId: 101}}},
	} {
		if _, _, err := authorizeTrafficUpload(nil, rpcutils.UserTypeDNS, 70, input); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("DNS credential submitted HTTP billing records: %v", err)
		}
	}
}

func TestSecurityAccessLogsBindNodeAndCluster(t *testing.T) {
	installTelemetryFixture(t)
	service := &HTTPAccessLogService{}
	ctx := rpcutils.NewMockNodeContext(7)
	for _, log := range []*pb.HTTPAccessLog{
		{NodeId: 8, ServerId: 101, Timestamp: time.Now().Unix()},
		{NodeId: 7, ServerId: 103, Timestamp: time.Now().Unix()},
		{NodeId: 7, ServerId: 101, Timestamp: time.Now().Unix(), BytesSent: -1},
	} {
		if _, err := service.CreateHTTPAccessLogs(ctx, &pb.CreateHTTPAccessLogsRequest{HttpAccessLogs: []*pb.HTTPAccessLog{log}}); err == nil {
			t.Fatal("forged node, cross-cluster server or negative access log accepted")
		}
	}
}
