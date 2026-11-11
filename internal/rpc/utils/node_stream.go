//go:build !plus

package rpcutils

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewNodeStreamValidator authenticates the initial signed handshake and returns
// an authoritative validator for the resulting session. The session remains
// bound to that credential and enabled node even after the handshake expires.
func NewNodeStreamValidator(ctx context.Context) (int64, func() error, error) {
	return newNodeStreamValidator(ctx, findNodeStreamCredential, findNodeStreamID)
}

func findNodeStreamCredential(machineID string) (*models.ApiToken, error) {
	one, err := models.SharedApiTokenDAO.Query(nil).Reuse(false).
		Attr("nodeId", machineID).State(models.ApiTokenStateEnabled).Find()
	if err != nil || one == nil {
		return nil, err
	}
	return one.(*models.ApiToken), nil
}

func findNodeStreamID(role UserType, machineID string) (int64, error) {
	if role != UserTypeNode {
		return 0, status.Error(codes.Unauthenticated, "unsupported stream machine role")
	}
	// The normal node-ID helper has a process-local TTL cache. Stream revocation
	// must observe node and cluster state on every check across all API nodes.
	one, err := models.SharedNodeDAO.Query(nil).Reuse(false).
		State(models.NodeStateEnabled).Attr("uniqueId", machineID).
		Result("id", "clusterId").Find()
	if err != nil || one == nil {
		return 0, err
	}
	node := one.(*models.Node)
	if node.ClusterId == 0 {
		return 0, nil
	}
	clusterEnabled, err := models.SharedNodeClusterDAO.Query(nil).Reuse(false).
		Pk(node.ClusterId).State(models.NodeClusterStateEnabled).Attr("isOn", true).Exist()
	if err != nil || !clusterEnabled {
		return 0, err
	}
	return int64(node.Id), nil
}

func newNodeStreamValidator(ctx context.Context,
	findCredential func(string) (*models.ApiToken, error),
	findNodeID func(UserType, string) (int64, error)) (int64, func() error, error) {
	var machineID string
	var initial *models.ApiToken
	_, nodeID, _, err := validateRequest(ctx, func(id string) (*models.ApiToken, error) {
		machineID = id
		var err error
		initial, err = findCredential(id)
		return initial, err
	}, findNodeID, UserTypeNode)
	if err != nil {
		return 0, nil, err
	}
	if initial == nil || machineID == "" || nodeID <= 0 {
		return 0, nil, status.Error(codes.Unauthenticated, "node stream requires signed machine authentication")
	}
	fingerprint := sha256.Sum256([]byte(initial.Secret))
	role := initial.Role
	validate := func() error {
		current, err := findCredential(machineID)
		if err != nil {
			return status.Error(codes.Unavailable, "cannot revalidate node stream credential")
		}
		if current == nil || current.Role != role {
			return status.Error(codes.Unauthenticated, "node stream credential was revoked")
		}
		currentFingerprint := sha256.Sum256([]byte(current.Secret))
		if subtle.ConstantTimeCompare(fingerprint[:], currentFingerprint[:]) != 1 {
			return status.Error(codes.Unauthenticated, "node stream credential changed")
		}
		currentNodeID, err := findNodeID(role, machineID)
		if err != nil {
			return status.Error(codes.Unavailable, "cannot revalidate node stream identity")
		}
		if currentNodeID != nodeID {
			return status.Error(codes.Unauthenticated, "node stream identity is no longer enabled")
		}
		return nil
	}
	return nodeID, validate, nil
}
