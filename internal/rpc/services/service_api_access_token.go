package services

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/utils/principals"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
)

// APIAccessTokenService AccessToken相关服务
type APIAccessTokenService struct {
	BaseService
	findAccessKey func(string) (*models.UserAccessKey, error)
}

// GetAPIAccessToken 获取AccessToken
func (this *APIAccessTokenService) GetAPIAccessToken(ctx context.Context, req *pb.GetAPIAccessTokenRequest) (*pb.GetAPIAccessTokenResponse, error) {
	if req.Type != "user" && req.Type != "admin" {
		return nil, errors.New("unsupported type '" + req.Type + "'")
	}

	var tx = this.NullTx()

	findAccessKey := this.findAccessKey
	if findAccessKey == nil {
		findAccessKey = func(id string) (*models.UserAccessKey, error) {
			return models.SharedUserAccessKeyDAO.FindAccessKeyWithUniqueId(tx, id)
		}
	}
	accessKey, err := findAccessKey(req.AccessKeyId)
	if err != nil {
		return nil, err
	}
	if accessKey == nil {
		return nil, errors.New("access key not found")
	}
	if subtle.ConstantTimeCompare([]byte(accessKey.Secret), []byte(req.AccessKey)) != 1 {
		return nil, errors.New("access key not found")
	}
	// Reject historical mixed keys instead of silently preferring AdminId.
	if err = principals.ValidateRoleSubject(req.Type, int64(accessKey.AdminId), int64(accessKey.UserId)); err != nil {
		return nil, errors.New("access key not found")
	}

	// 检查数据
	switch req.Type {
	case "user":
		// TODO 将来支持子用户
		if accessKey.UserId == 0 {
			return nil, errors.New("access key not found")
		}

		// 检查用户状态
		user, err := models.SharedUserDAO.FindEnabledUser(tx, int64(accessKey.UserId), nil)
		if err != nil {
			return nil, err
		}
		if user == nil || !user.IsOn {
			return nil, errors.New("the user is not available")
		}
	case "admin":
		if accessKey.AdminId == 0 {
			return nil, errors.New("access key not found")
		}

		// 检查管理员状态
		admin, err := models.SharedAdminDAO.FindEnabledAdmin(tx, int64(accessKey.AdminId))
		if err != nil {
			return nil, err
		}
		if admin == nil || !admin.IsOn {
			return nil, errors.New("the admin is not available")
		}
	default:
		return nil, errors.New("invalid type '" + req.Type + "'")
	}

	// 更新AccessKey访问时间
	err = models.SharedUserAccessKeyDAO.UpdateAccessKeyAccessedAt(tx, int64(accessKey.Id))
	if err != nil {
		return nil, err
	}

	// 创建AccessToken
	token, expiresAt, err := models.SharedAPIAccessTokenDAO.GenerateAccessToken(tx, int64(accessKey.AdminId), int64(accessKey.UserId))
	if err != nil {
		return nil, err
	}

	return &pb.GetAPIAccessTokenResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}
