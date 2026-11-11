package configs

import (
	"reflect"
	"testing"

	"github.com/iwind/TeaGo/dbs"
	yaml "go.yaml.in/yaml/v3"
	legacyyaml "gopkg.in/yaml.v3"
)

func TestYAMLDatabaseConfigurationInteroperability(t *testing.T) {
	fixture := []byte("user: '00123'\npassword: 'yes: # example'\ndatabase: edge_test\nhost: '[2001:db8::1]:3306'\nboolFields: [isOn, isAvailable]\n")
	var legacy SimpleDBConfig
	if err := legacyyaml.Unmarshal(fixture, &legacy); err != nil {
		t.Fatal(err)
	}
	actual, err := ParseSimpleDBConfig(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*actual, legacy) || actual.User != "00123" || actual.Password != "yes: # example" {
		t.Fatal("simple database configuration changed during YAML migration")
	}

	// GenerateOldConfig passes this exact TeaGo type across module boundaries.
	var generated dbs.Config
	generated.Default.DB = "dev"
	generated.DBs = map[string]*dbs.DBConfig{"dev": {
		Driver: "mysql", Dsn: "user:example@tcp([2001:db8::1]:3306)/edge_test?charset=utf8mb4", Prefix: "edge",
	}}
	generated.DBs["dev"].Models.Package = "internal/db/models"
	generated.Fields = map[string][]string{"bool": actual.BoolFields}
	encoded, err := yaml.Marshal(&generated)
	if err != nil {
		t.Fatal(err)
	}
	var decoded dbs.Config
	if err := legacyyaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, generated) {
		t.Fatal("maintained YAML output cannot be read by TeaGo's legacy decoder")
	}
}
