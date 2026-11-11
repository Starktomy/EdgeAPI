package services

import (
	"context"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	rpcutils "github.com/TeaOSLab/EdgeAPI/internal/rpc/utils"
)

// Keep object authorization at the RPC boundary, including calls that bypass
// the Admin UI. The store also allows permission denials to be tested without
// connecting tests to an installation's database.
type resourceAuthorizer interface {
	CheckUserHeader(userId int64, headerId int64) error
	CheckUserWebsocket(userId int64, websocketId int64) error
	CheckUserWeb(userId int64, webId int64) error
	CheckUserServer(userId int64, serverId int64) error
	IsSuperAdmin(adminId int64) (bool, error)
}

type databaseAuthorizer struct{}

func (databaseAuthorizer) CheckUserHeader(userId int64, headerId int64) error {
	return models.SharedHTTPHeaderDAO.CheckUserHeader(nil, userId, headerId)
}

func (databaseAuthorizer) CheckUserWebsocket(userId int64, websocketId int64) error {
	return models.SharedHTTPWebsocketDAO.CheckUserWebsocket(nil, userId, websocketId)
}

func (databaseAuthorizer) CheckUserWeb(userId int64, webId int64) error {
	return models.SharedHTTPWebDAO.CheckUserWeb(nil, userId, webId)
}

func (databaseAuthorizer) CheckUserServer(userId int64, serverId int64) error {
	return models.SharedServerDAO.CheckUserServer(nil, userId, serverId)
}

func (databaseAuthorizer) IsSuperAdmin(adminId int64) (bool, error) {
	admin, err := models.SharedAdminDAO.FindEnabledAdmin(nil, adminId)
	if err != nil || admin == nil {
		return false, err
	}
	return admin.IsOn && admin.IsSuper, nil
}

func (this *BaseService) authorizer() resourceAuthorizer {
	if this.authorization != nil {
		return this.authorization
	}
	return databaseAuthorizer{}
}

func (this *BaseService) ValidateSuperAdmin(ctx context.Context) (int64, error) {
	adminId, err := this.ValidateAdmin(ctx)
	if err != nil {
		return 0, err
	}
	if adminId <= 0 {
		return 0, this.PermissionError()
	}
	isSuper, err := this.authorizer().IsSuperAdmin(adminId)
	if err != nil {
		return 0, err
	}
	if !isSuper {
		return 0, this.PermissionError()
	}
	return adminId, nil
}

// Admin0 is a signed service credential used during installation and first
// password setup. REST account tokens can never carry this service identity.
func (this *BaseService) validateAdminAccountMutation(ctx context.Context, targetAdminId int64, allowSelf bool) error {
	role, _, adminId, err := rpcutils.ValidateRequest(ctx, rpcutils.UserTypeAdmin, rpcutils.UserTypeAPI)
	if err != nil {
		return err
	}
	if !rpcutils.IsRest(ctx) && (role == rpcutils.UserTypeAPI || (role == rpcutils.UserTypeAdmin && adminId == 0)) {
		return nil
	}
	if allowSelf && role == rpcutils.UserTypeAdmin && adminId > 0 && adminId == targetAdminId {
		return nil
	}
	_, err = this.ValidateSuperAdmin(ctx)
	return err
}
