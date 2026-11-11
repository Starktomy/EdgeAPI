//go:build !plus

package rpcutils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"time"

	teaconst "github.com/TeaOSLab/EdgeAPI/internal/const"
	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/db/models/authority"
	"github.com/TeaOSLab/EdgeAPI/internal/encrypt"
	"github.com/TeaOSLab/EdgeAPI/internal/errors"
	"github.com/TeaOSLab/EdgeAPI/internal/utils"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
	"github.com/iwind/TeaGo/lists"
	"google.golang.org/grpc/metadata"
)

type requestClaims struct {
	Type      UserType `json:"type"`
	UserId    int64    `json:"userId"`
	Timestamp int64    `json:"timestamp"`
}

func authenticateClaims(token string, secret string, nodeId string) (requestClaims, error) {
	var claims requestClaims
	if strings.HasPrefix(token, "v2.") {
		verified, err := rpcauth.Verify(token, secret, nodeId)
		if err != nil {
			return claims, err
		}
		return requestClaims{Type: verified.Type, UserId: verified.UserID, Timestamp: verified.IssuedAt}, nil
	}
	// This opt-in only exists for a coordinated rolling migration. Encryption
	// without a MAC does not authenticate legacy claims; never enable by default.
	if os.Getenv("EDGE_ALLOW_LEGACY_RPC_TOKENS") != "true" || len(token) > rpcauth.MaxTokenSize {
		return claims, errors.New("legacy RPC tokens are disabled")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil {
		return claims, err
	}
	method, err := encrypt.NewMethodInstance(teaconst.EncryptMethod, secret, nodeId)
	if err != nil {
		return claims, err
	}
	data, err = method.Decrypt(data)
	if err != nil {
		return claims, err
	}
	if err = json.Unmarshal(data, &claims); err != nil {
		return claims, err
	}
	now := time.Now()
	if claims.Timestamp <= 0 || claims.Timestamp < now.Add(-rpcauth.Lifetime-rpcauth.ClockSkew).Unix() || claims.Timestamp > now.Add(rpcauth.ClockSkew).Unix() {
		return claims, errors.New("legacy RPC token timestamp is outside the migration validity window")
	}
	return claims, nil
}

// A service may only delegate roles explicitly granted to its machine identity.
// Admin's APIContext is used by installation/upgrade, so that delegation is
// retained; a node, cluster or user portal cannot claim admin or API privileges.
func validateDelegatedRole(machineRole UserType, claimedRole UserType) error {
	switch machineRole {
	case UserTypeAdmin:
		if claimedRole == UserTypeAdmin || claimedRole == UserTypeAPI {
			return nil
		}
	case UserTypeUser, UserTypeProvider, UserTypeNode, UserTypeCluster,
		UserTypeStat, UserTypeDNS, UserTypeLog, UserTypeAPI, UserTypeAuthority, UserTypeReport:
		if claimedRole == machineRole {
			return nil
		}
	}
	return errors.New("credential is not permitted to delegate the requested role")
}

func findRequestCredential(nodeId string) (*models.ApiToken, error) {
	return models.SharedApiTokenDAO.FindEnabledTokenWithNode(nil, nodeId)
}

func findRequestNodeId(role UserType, nodeId string) (int64, error) {
	switch role {
	case UserTypeNode:
		return models.SharedNodeDAO.FindEnabledNodeIdWithUniqueId(nil, nodeId)
	case UserTypeCluster:
		return models.SharedNodeClusterDAO.FindEnabledClusterIdWithUniqueId(nil, nodeId)
	case UserTypeUser:
		return models.SharedUserNodeDAO.FindEnabledUserNodeIdWithUniqueId(nil, nodeId)
	case UserTypeDNS:
		return models.SharedNSNodeDAO.FindEnabledNodeIdWithUniqueId(nil, nodeId)
	case UserTypeReport:
		return models.SharedReportNodeDAO.FindEnabledNodeIdWithUniqueId(nil, nodeId)
	case UserTypeAuthority:
		return authority.SharedAuthorityNodeDAO.FindEnabledAuthorityNodeIdWithUniqueId(nil, nodeId)
	}
	return 0, nil
}

// ValidateRequest 校验请求
func ValidateRequest(ctx context.Context, userTypes ...UserType) (userType UserType, resultNodeId int64, userId int64, err error) {
	return validateRequest(ctx, findRequestCredential, findRequestNodeId, userTypes...)
}

func validateRequest(ctx context.Context,
	findCredential func(string) (*models.ApiToken, error),
	findNodeId func(UserType, string) (int64, error),
	userTypes ...UserType) (userType UserType, resultNodeId int64, userId int64, err error) {
	if ctx == nil {
		err = errors.New("context should not be nil")
		return
	}

	// 支持直接认证
	plainCtx, ok := ctx.(*PlainContext)
	if ok {
		userType = plainCtx.UserType
		userId = plainCtx.UserId

		if (userType != UserTypeAdmin && userType != UserTypeUser) ||
			(len(userTypes) > 0 && !lists.ContainsString(userTypes, userType)) {
			userType = UserTypeNone
			userId = 0
		}

		if userId <= 0 {
			err = errors.New("context: can not find user or permission denied")
		}

		return
	}

	// 是否是模拟测试
	{
		mockCtx, isMock := ctx.(*MockNodeContext)
		if isMock {
			if len(userTypes) > 0 && !lists.ContainsString(userTypes, UserTypeNode) {
				return UserTypeNone, 0, 0, errors.New("unsupported mock node role")
			}
			return UserTypeNode, mockCtx.NodeId, mockCtx.NodeId, nil
		}
	}

	{
		mockCtx, isMock := ctx.(*MockAdminNodeContext)
		if isMock {
			if len(userTypes) > 0 && !lists.ContainsString(userTypes, UserTypeAdmin) {
				return UserTypeNone, 0, 0, errors.New("unsupported mock admin role")
			}
			return UserTypeAdmin, 0, mockCtx.AdminId, nil
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return UserTypeNone, 0, 0, errors.New("context: need 'nodeId'")
	}
	nodeIds := md.Get("nodeid")
	if len(nodeIds) != 1 || len(nodeIds[0]) == 0 || len(nodeIds[0]) > 256 {
		return UserTypeNone, 0, 0, errors.New("context: need 'nodeId'")
	}
	nodeId := nodeIds[0]
	tokens := md.Get("token")
	if len(tokens) != 1 || len(tokens[0]) == 0 || len(tokens[0]) > rpcauth.MaxTokenSize {
		return UserTypeNone, 0, 0, errors.New("context: invalid 'token'")
	}
	token := tokens[0]
	if !strings.HasPrefix(token, "v2.") && os.Getenv("EDGE_ALLOW_LEGACY_RPC_TOKENS") != "true" {
		return UserTypeNone, 0, 0, errors.New("legacy RPC tokens are disabled")
	}

	// 获取角色Node信息
	apiToken, err := findCredential(nodeId)
	if err != nil {
		utils.PrintError(err)
		return UserTypeNone, 0, 0, err
	}
	if apiToken == nil {
		return UserTypeNone, 0, 0, errors.New("context: can not find api token for node '" + nodeId + "'")
	}

	claims, err := authenticateClaims(token, apiToken.Secret, nodeId)
	if err != nil {
		return UserTypeNone, 0, 0, errors.New("decode token error: " + err.Error())
	}

	t := claims.Type
	if err = validateDelegatedRole(apiToken.Role, t); err != nil {
		return UserTypeNone, 0, 0, err
	}
	if claims.UserId < 0 {
		return UserTypeNone, 0, 0, errors.New("invalid account identity")
	}
	if len(userTypes) > 0 && !lists.ContainsString(userTypes, t) {
		return UserTypeNone, 0, 0, errors.New("not supported node type: '" + t + "'")
	}

	switch apiToken.Role {
	case UserTypeNode, UserTypeCluster, UserTypeUser, UserTypeDNS, UserTypeReport, UserTypeAuthority:
		resultNodeId, err = findNodeId(apiToken.Role, nodeId)
		if err != nil {
			return UserTypeNone, 0, 0, errors.New("context: " + err.Error())
		}
		if resultNodeId <= 0 {
			return UserTypeNone, 0, 0, errors.New("context: node identity is not available")
		}
		if apiToken.Role != UserTypeUser {
			return t, resultNodeId, resultNodeId, nil
		}
	}
	return t, resultNodeId, claims.UserId, nil
}
