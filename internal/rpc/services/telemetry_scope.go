package services

import (
	"strings"
	"time"
	"unicode"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/iwind/TeaGo/dbs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func validateTrafficUpload(req *pb.UploadServerDailyStatsRequest, now time.Time) error {
	if req == nil || len(req.Stats)+len(req.DomainStats) > 2000 || proto.Size(req) > 4<<20 {
		return status.Error(codes.InvalidArgument, "statistics batch exceeds 2000 records or 4 MiB")
	}
	valid := func(created, bytes, cached, requests, cachedRequests, attacks, attackBytes int64) bool {
		return created >= 1577836800 && created <= now.Unix()+300 && bytes >= 0 && bytes <= 1<<46 &&
			cached >= 0 && cached <= bytes && requests >= 0 && requests <= 1<<40 &&
			cachedRequests >= 0 && cachedRequests <= requests && attacks >= 0 && attacks <= requests &&
			attackBytes >= 0 && attackBytes <= 1<<46
	}
	for _, stat := range req.Stats {
		if stat == nil || stat.ServerId < 0 || stat.UserId < 0 || stat.PlanId < 0 || stat.NodeRegionId < 0 ||
			!valid(stat.CreatedAt, stat.Bytes, stat.CachedBytes, stat.CountRequests, stat.CountCachedRequests, stat.CountAttackRequests, stat.AttackBytes) {
			return status.Error(codes.InvalidArgument, "invalid server traffic statistics")
		}
	}
	for _, stat := range req.DomainStats {
		if stat == nil || stat.ServerId <= 0 || len(stat.Domain) > 253 || strings.IndexFunc(stat.Domain, unicode.IsControl) >= 0 ||
			!valid(stat.CreatedAt, stat.Bytes, stat.CachedBytes, stat.CountRequests, stat.CountCachedRequests, stat.CountAttackRequests, stat.AttackBytes) {
			return status.Error(codes.InvalidArgument, "invalid domain traffic statistics")
		}
	}
	return nil
}

type telemetryScope struct {
	clusters map[int64]bool
	regionID int64
	servers  map[int64]*models.Server
}

func loadTelemetryScope(tx *dbs.Tx, nodeID int64) (*telemetryScope, error) {
	one, err := models.SharedNodeDAO.Query(tx).Reuse(false).Pk(nodeID).Result("id", "regionId", "clusterId", "secondaryClusterIds").Find()
	if err != nil {
		return nil, err
	}
	if one == nil {
		return nil, status.Error(codes.PermissionDenied, "node no longer exists")
	}
	node := one.(*models.Node)
	scope := &telemetryScope{clusters: map[int64]bool{}, regionID: int64(node.RegionId), servers: map[int64]*models.Server{}}
	if node.ClusterId > 0 {
		scope.clusters[int64(node.ClusterId)] = true
	}
	for _, clusterID := range node.DecodeSecondaryClusterIds() {
		if clusterID > 0 {
			scope.clusters[clusterID] = true
		}
	}
	return scope, nil
}

func (scope *telemetryScope) server(tx *dbs.Tx, serverID int64) (*models.Server, error) {
	if server := scope.servers[serverID]; server != nil {
		return server, nil
	}
	one, err := models.SharedServerDAO.Query(tx).Reuse(false).Pk(serverID).Result("id", "clusterId", "userId", "userPlanId", "lastUserPlanId").Find()
	if err != nil {
		return nil, err
	}
	if one == nil || !scope.clusters[int64(one.(*models.Server).ClusterId)] {
		return nil, status.Error(codes.PermissionDenied, "server is outside authenticated node clusters")
	}
	server := one.(*models.Server)
	scope.servers[serverID] = server
	return server, nil
}

// Normalize a private copy, keeping the original wire payload stable for receipt
// hashing. Ownership, region and quota enforcement come from server records.
// Preserve a validated historical plan ID rather than re-billing old traffic
// against the server's currently selected plan.
func authorizeTrafficUpload(tx *dbs.Tx, role string, nodeID int64, input *pb.UploadServerDailyStatsRequest) (*pb.UploadServerDailyStatsRequest, map[int64]int64, error) {
	req := proto.Clone(input).(*pb.UploadServerDailyStatsRequest)
	clusterByServer := map[int64]int64{}
	if role == rpcutils.UserTypeDNS {
		// DNS telemetry has no authority to charge HTTP services or their users.
		clusterID, err := models.SharedNSNodeDAO.FindNodeClusterId(tx, nodeID)
		if err != nil {
			return nil, nil, err
		}
		if clusterID <= 0 || len(req.DomainStats) > 0 {
			return nil, nil, status.Error(codes.PermissionDenied, "invalid DNS statistics scope")
		}
		clusterByServer[0] = clusterID
		for _, stat := range req.Stats {
			if stat.ServerId != 0 || stat.UserId != 0 || stat.PlanId != 0 {
				return nil, nil, status.Error(codes.PermissionDenied, "DNS nodes cannot submit HTTP service traffic")
			}
			stat.CheckTrafficLimiting = false
			stat.NodeRegionId = 0
		}
		return req, clusterByServer, nil
	}
	scope, err := loadTelemetryScope(tx, nodeID)
	if err != nil {
		return nil, nil, err
	}
	for _, stat := range req.Stats {
		server, err := scope.server(tx, stat.ServerId)
		if err != nil {
			return nil, nil, err
		}
		if stat.UserId != 0 && stat.UserId != int64(server.UserId) {
			return nil, nil, status.Error(codes.PermissionDenied, "statistics user does not own server")
		}
		stat.UserId = int64(server.UserId)
		stat.NodeRegionId = scope.regionID
		stat.CheckTrafficLimiting = true
		planAllowed := stat.PlanId == 0 && (server.UserPlanId == 0 || server.LastUserPlanId == 0)
		for _, userPlanID := range []uint32{server.UserPlanId, server.LastUserPlanId} {
			if userPlanID == 0 || planAllowed {
				continue
			}
			plan, err := models.SharedUserPlanDAO.FindUserPlanWithoutState(tx, int64(userPlanID), nil)
			if err != nil {
				return nil, nil, err
			}
			if plan != nil && plan.UserId == server.UserId && stat.PlanId == int64(plan.PlanId) {
				planAllowed = true
			}
		}
		if !planAllowed {
			return nil, nil, status.Error(codes.PermissionDenied, "traffic plan is not a retained server plan; operator reconciliation required")
		}
		clusterByServer[stat.ServerId] = int64(server.ClusterId)
	}
	for _, stat := range req.DomainStats {
		server, err := scope.server(tx, stat.ServerId)
		if err != nil {
			return nil, nil, err
		}
		clusterByServer[stat.ServerId] = int64(server.ClusterId)
	}
	return req, clusterByServer, nil
}
