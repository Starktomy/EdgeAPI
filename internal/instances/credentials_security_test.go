package instances

import (
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestSecurityInstallerDatabaseConfigurationRequiresExplicitPassword(t *testing.T) {
	var options Options
	options.DB.Host, options.DB.Username, options.DB.Name, options.DB.Port = "127.0.0.1", "fixture", "fixture", 3306
	instance := NewInstance(options)
	if _, err := instance.databaseConfig(true); err == nil {
		t.Fatal("installer accepted an empty/default database credential")
	}
	if err := instance.SetupDB(); err == nil {
		t.Fatal("installer reached database setup without explicit credentials")
	}
}

func TestSecurityInstallerDSNPreservesCredentialAndIPv6Values(t *testing.T) {
	var options Options
	options.DB.Host, options.DB.Username, options.DB.Name, options.DB.Port = "2001:db8::1", "fixture", "fixture db", 3306
	options.DB.Password = " exact-secret:@/value 安装 "
	instance := NewInstance(options)
	for _, withDatabase := range []bool{false, true} {
		config, err := instance.databaseConfig(withDatabase)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := mysql.ParseDSN(config.Dsn)
		if err != nil || decoded.Passwd != options.DB.Password || decoded.Addr != "[2001:db8::1]:3306" || decoded.User != options.DB.Username {
			t.Fatalf("installer corrupted explicit connection settings: %v", err)
		}
		if withDatabase && decoded.DBName != options.DB.Name || !withDatabase && decoded.DBName != "" {
			t.Fatal("installer connected to the wrong database")
		}
	}
}
