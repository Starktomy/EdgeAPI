package services

import (
	"context"

	teaconst "github.com/TeaOSLab/EdgeAPI/internal/const"
	"github.com/TeaOSLab/EdgeAPI/internal/errors"
	"github.com/TeaOSLab/EdgeAPI/internal/rpc"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
	"github.com/iwind/TeaGo/dbs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type BaseService struct {
	authorization resourceAuthorizer
}

// ValidateAdmin 校验管理员
func (this *BaseService) ValidateAdmin(ctx context.Context) (adminId int64, err error) {
	_, _, reqUserId, err := rpcutils.ValidateRequest(ctx, rpcutils.UserTypeAdmin)
	if err != nil {
		return
	}
	return reqUserId, nil
}

// ValidateAdminAndUser 校验管理员和用户
func (this *BaseService) ValidateAdminAndUser(ctx context.Context, canRest bool) (adminId int64, userId int64, err error) {
	reqUserType, _, reqUserId, err := rpcutils.ValidateRequest(ctx, rpcutils.UserTypeAdmin, rpcutils.UserTypeUser)
	if err != nil {
		return
	}

	adminId = int64(0)
	userId = int64(0)
	switch reqUserType {
	case rpcutils.UserTypeAdmin:
		adminId = reqUserId
		if adminId < 0 { // 允许AdminId = 0
			err = errors.New("invalid 'adminId'")
			return
		}
	case rpcutils.UserTypeUser:
		userId = reqUserId
		if userId <= 0 { // A portal service without a logged-in user is not a tenant.
			err = errors.New("invalid 'userId'")
			return
		}
	default:
		err = errors.New("invalid user type")
	}

	if err != nil {
		return
	}

	if userId > 0 && !canRest && rpcutils.IsRest(ctx) {
		err = errors.New("can not be called by rest")
		return
	}

	return
}

// ValidateNode 校验边缘节点
func (this *BaseService) ValidateNode(ctx context.Context) (nodeId int64, err error) {
	_, _, nodeId, err = rpcutils.ValidateRequest(ctx, rpcutils.UserTypeNode)
	return
}

// ValidateNSNode 校验DNS节点
func (this *BaseService) ValidateNSNode(ctx context.Context) (nodeId int64, err error) {
	_, _, nodeId, err = rpcutils.ValidateRequest(ctx, rpcutils.UserTypeDNS)
	return
}

// ValidateUserNode 校验用户节点
func (this *BaseService) ValidateUserNode(ctx context.Context, canRest bool) (userId int64, err error) {
	// 不允许REST调用
	if !canRest && rpcutils.IsRest(ctx) {
		err = errors.New("can not be called by rest")
		return
	}

	_, _, userId, err = rpcutils.ValidateRequest(ctx, rpcutils.UserTypeUser)
	return
}

// ValidateAuthorityNode 校验认证节点
func (this *BaseService) ValidateAuthorityNode(ctx context.Context) (nodeId int64, err error) {
	_, _, nodeId, err = rpcutils.ValidateRequest(ctx, rpcutils.UserTypeAuthority)
	return
}

// ValidateNodeId 获取节点ID
func (this *BaseService) ValidateNodeId(ctx context.Context, roles ...rpcutils.UserType) (role rpcutils.UserType, nodeIntId int64, err error) {
	if len(roles) == 0 {
		roles = []rpcutils.UserType{rpcutils.UserTypeNode, rpcutils.UserTypeCluster, rpcutils.UserTypeAdmin, rpcutils.UserTypeUser, rpcutils.UserTypeDNS, rpcutils.UserTypeReport, rpcutils.UserTypeLog, rpcutils.UserTypeAPI}
	}
	if rpcutils.IsRest(ctx) {
		return rpcutils.UserTypeNone, 0, this.PermissionError()
	}
	role, nodeIntId, _, err = rpcutils.ValidateRequest(ctx, roles...)
	return
}

// Success 返回成功
func (this *BaseService) Success() (*pb.RPCSuccess, error) {
	return &pb.RPCSuccess{}, nil
}

// SuccessCount 返回数字
func (this *BaseService) SuccessCount(count int64) (*pb.RPCCountResponse, error) {
	return &pb.RPCCountResponse{Count: count}, nil
}

// Exists 返回是否存在
func (this *BaseService) Exists(b bool) (*pb.RPCExists, error) {
	return &pb.RPCExists{Exists: b}, nil
}

// PermissionError 返回权限错误
func (this *BaseService) PermissionError() error {
	return errors.New("Permission Denied")
}

func (this *BaseService) NotImplementedYet() error {
	return status.Error(codes.Unimplemented, "not implemented yet")
}

// NullTx 空的数据库事务
func (this *BaseService) NullTx() *dbs.Tx {
	return nil
}

// RunTx 在当前数据中执行一个事务
func (this *BaseService) RunTx(callback func(tx *dbs.Tx) error) error {
	db, err := dbs.Default()
	if err != nil {
		return err
	}
	return db.RunTx(callback)
}

// BeginTag 开始标签统计
func (this *BaseService) BeginTag(ctx context.Context, name string) {
	if !teaconst.Debug {
		return
	}
	traceCtx, ok := ctx.(*rpc.Context)
	if ok {
		traceCtx.Begin(name)
	}
}

// EndTag 结束标签统计
func (this *BaseService) EndTag(ctx context.Context, name string) {
	if !teaconst.Debug {
		return
	}
	traceCtx, ok := ctx.(*rpc.Context)
	if ok {
		traceCtx.End(name)
	}
}
