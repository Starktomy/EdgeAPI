//go:build !plus

package rpcutils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	teaconst "github.com/TeaOSLab/EdgeAPI/internal/const"
	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/encrypt"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
	"google.golang.org/grpc/metadata"
)

func signedRequestContext(t *testing.T, nodeId string, secret string, role UserType, userId int64) context.Context {
	t.Helper()
	token, err := rpcauth.Sign(secret, nodeId, role, userId)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("nodeid", nodeId, "token", token))
}

func legacyRequestToken(t *testing.T, nodeId string, secret string, role UserType, userId int64, timestamp int64) string {
	t.Helper()
	method, err := encrypt.NewMethodInstance(teaconst.EncryptMethod, secret, nodeId)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(requestClaims{Type: role, UserId: userId, Timestamp: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	data, err = method.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func TestSecurityRequestRoleDelegation(t *testing.T) {
	const nodeId = "security-test-node"
	const secret = "security-test-secret"
	for _, test := range []struct {
		name        string
		machineRole UserType
		claimedRole UserType
		allowed     bool
	}{
		{"node role", UserTypeNode, UserTypeNode, true},
		{"node cannot become admin", UserTypeNode, UserTypeAdmin, false},
		{"node cannot read API credentials", UserTypeNode, UserTypeAPI, false},
		{"cluster cannot become admin", UserTypeCluster, UserTypeAdmin, false},
		{"user portal cannot become API", UserTypeUser, UserTypeAPI, false},
		{"admin role", UserTypeAdmin, UserTypeAdmin, true},
		{"admin installation API delegation", UserTypeAdmin, UserTypeAPI, true},
		{"API cannot become admin", UserTypeAPI, UserTypeAdmin, false},
		{"unknown credential role", "invalid", "invalid", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := signedRequestContext(t, nodeId, secret, test.claimedRole, 3)
			role, _, _, err := validateRequest(ctx, func(id string) (*models.ApiToken, error) {
				return &models.ApiToken{NodeId: nodeId, Secret: secret, Role: test.machineRole}, nil
			}, func(role UserType, id string) (int64, error) { return 7, nil }, test.claimedRole)
			if (err == nil) != test.allowed {
				t.Fatalf("machine=%q claimed=%q: %v", test.machineRole, test.claimedRole, err)
			}
			if err == nil && role != test.claimedRole {
				t.Fatalf("returned role %q", role)
			}
		})
	}
}

func TestSecurityRequestBindsNodeIdentity(t *testing.T) {
	const secret = "security-test-secret-at-least-32-bytes"
	ctx := signedRequestContext(t, "node", secret, UserTypeNode, 999)
	_, nodeId, accountId, err := validateRequest(ctx, func(string) (*models.ApiToken, error) {
		return &models.ApiToken{Secret: secret, Role: UserTypeNode}, nil
	}, func(UserType, string) (int64, error) { return 7, nil }, UserTypeNode)
	if err != nil || nodeId != 7 || accountId != 7 {
		t.Fatalf("identity=(%d,%d), err=%v; want authenticated node 7", nodeId, accountId, err)
	}
}

func TestSecurityRequestCredentialRevocation(t *testing.T) {
	const secret = "security-test-secret-at-least-32-bytes"
	ctx := signedRequestContext(t, "node", secret, UserTypeNode, 0)
	revoked := false
	lookup := func(string) (*models.ApiToken, error) {
		if revoked {
			return nil, nil
		}
		return &models.ApiToken{Secret: secret, Role: UserTypeNode}, nil
	}
	resolve := func(UserType, string) (int64, error) { return 7, nil }
	if _, _, _, err := validateRequest(ctx, lookup, resolve, UserTypeNode); err != nil {
		t.Fatal(err)
	}
	revoked = true
	if _, _, _, err := validateRequest(ctx, lookup, resolve, UserTypeNode); err == nil {
		t.Fatal("revoked credential remained usable")
	}
}

func TestSecurityRESTPrincipalCannotClaimMachineRole(t *testing.T) {
	if _, _, _, err := ValidateRequest(NewPlainContext(UserTypeAPI, 1), UserTypeAPI); err == nil {
		t.Fatal("REST account context must not carry a machine API role")
	}
	if _, _, _, err := ValidateRequest(NewPlainContext(UserTypeUser, 0), UserTypeUser); err == nil {
		t.Fatal("REST user requires a positive user identity")
	}
}

func TestSecurityLegacyTokensRequireMigrationFlagAndFreshTimestamp(t *testing.T) {
	const secret = "security-test-secret-at-least-32-bytes"
	token := legacyRequestToken(t, "node", secret, UserTypeNode, 0, time.Now().Unix())
	t.Setenv("EDGE_ALLOW_LEGACY_RPC_TOKENS", "")
	if _, err := authenticateClaims(token, secret, "node"); err == nil {
		t.Fatal("legacy token accepted by default")
	}
	t.Setenv("EDGE_ALLOW_LEGACY_RPC_TOKENS", "true")
	if _, err := authenticateClaims(token, secret, "node"); err != nil {
		t.Fatalf("explicit migration rejected a fresh legacy token: %v", err)
	}
	for _, timestamp := range []int64{0, time.Now().Add(-3 * time.Minute).Unix(), time.Now().Add(time.Minute).Unix()} {
		old := legacyRequestToken(t, "node", secret, UserTypeNode, 0, timestamp)
		if _, err := authenticateClaims(old, secret, "node"); err == nil {
			t.Fatal("legacy token without a fresh timestamp was accepted")
		}
	}
	valid, err := rpcauth.Sign(secret, "node", UserTypeNode, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateClaims(valid+"tampered", secret, "node"); err == nil {
		t.Fatal("invalid v2 signature fell back to legacy authentication")
	}
}
