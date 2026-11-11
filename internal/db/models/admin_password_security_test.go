package models_test

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/passwords"
	"github.com/iwind/TeaGo/dbs"
)

func TestSecurityAdminPasswordMigratesOnSuccessfulRawLogin(t *testing.T) {
	const raw = "correct-password"
	sum := md5.Sum([]byte(raw))
	legacy := hex.EncodeToString(sum[:])
	store := &taskSecurityDriver{password: legacy}
	name := "edgeapi-security-password-" + strconv.FormatInt(taskSecurityDriverId.Add(1), 10)
	sql.Register(name, store)
	db, err := dbs.NewInstanceFromConfig(&dbs.DBConfig{Driver: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dao := &models.AdminDAO{DAOObject: dbs.DAOObject{Instance: db, Table: "edgeAdmins", PkName: "id", Model: new(models.Admin)}}
	if id, err := dao.CheckAdminPassword(nil, "admin", passwords.RawPrefix+"wrong"); id != 0 || err != nil || store.passwordUpdates != 0 {
		t.Fatalf("wrong password accepted/migrated: id=%d err=%v", id, err)
	}
	if id, err := dao.CheckAdminPassword(nil, "admin", legacy); id != 1 || err != nil || store.passwordUpdates != 0 {
		t.Fatalf("unmigrated legacy login rejected: id=%d err=%v", id, err)
	}
	if id, err := dao.CheckAdminPassword(nil, "admin", passwords.RawPrefix+raw); id != 1 || err != nil || store.passwordUpdates != 1 {
		t.Fatalf("successful raw login did not migrate: id=%d err=%v updates=%d", id, err, store.passwordUpdates)
	}
	if id, err := dao.CheckAdminPassword(nil, "admin", legacy); id != 0 || err != nil {
		t.Fatalf("legacy digest replay accepted after migration: id=%d err=%v", id, err)
	}
	if id, err := dao.CheckAdminPassword(nil, "admin", passwords.RawPrefix+raw); id != 1 || err != nil || store.passwordUpdates != 1 {
		t.Fatalf("Argon2id login failed or re-migrated: id=%d err=%v", id, err)
	}
	store.password = legacy
	store.replaceBeforeMigration = true
	if id, err := dao.CheckAdminPassword(nil, "admin", passwords.RawPrefix+raw); id != 0 || err != nil {
		t.Fatalf("concurrent password reset was overwritten/accepted: id=%d err=%v", id, err)
	}
}
