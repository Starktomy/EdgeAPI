// Copyright 2024 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/TeaOSLab/EdgeAPI/internal/instances"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
	_ "github.com/iwind/TeaGo/bootstrap"
	"github.com/iwind/TeaGo/lists"
)

func main() {
	var verbose = lists.ContainsString(os.Args, "-v")

	database, err := databaseSettingsFromEnv(os.LookupEnv)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	if !rpcauth.PlaintextAllowed("127.0.0.1") {
		log.Print("local instance installation requires EDGE_ALLOW_LOOPBACK_RPC=true, or explicitly configured verified TLS endpoints")
		os.Exit(2)
	}
	if verbose {
		database.log(log.Default())
	}

	var isTesting = lists.ContainsString(os.Args, "-test") || lists.ContainsString(os.Args, "--test")
	if isTesting {
		fmt.Println("testing mode ...")
	}

	var instance = instances.NewInstance(instances.Options{
		IsTesting: isTesting,
		Verbose:   verbose,
		Cacheable: false,
		WorkDir:   "",
		SrcDir:    "/usr/local/goedge/src",
		DB: struct {
			Host     string
			Port     int
			Username string
			Password string
			Name     string
		}{
			Host:     database.Host,
			Port:     3306,
			Username: "root",
			Password: database.Password,
			Name:     database.Name,
		},
		AdminNode: struct {
			Port int
		}{
			Port: 7788,
		},
		APINode: struct {
			HTTPPort     int
			RestHTTPPort int
		}{
			HTTPPort:     8001,
			RestHTTPPort: 8002,
		},
		Node: struct{ HTTPPort int }{
			HTTPPort: 80,
		},
		UserNode: struct {
			HTTPPort int
		}{
			HTTPPort: 7799,
		},
	})
	err = instance.SetupAll()
	if err != nil {
		fmt.Println("[ERROR]setup failed: " + err.Error())
		os.Exit(1)
	}

	fmt.Println("ok")
}

type databaseSettings struct {
	Host     string
	Name     string
	Password string
}

func databaseSettingsFromEnv(lookup func(string) (string, bool)) (databaseSettings, error) {
	config := databaseSettings{Host: "127.0.0.1", Name: "edges"}
	if host, _ := lookup("EDGE_DB_HOST"); host != "" {
		config.Host = host
	}
	if name, _ := lookup("EDGE_DB_NAME"); name != "" {
		config.Name = name
	}
	password, set := lookup("EDGE_DB_PASSWORD")
	if !set || password == "" {
		return databaseSettings{}, fmt.Errorf("EDGE_DB_PASSWORD must be explicitly set to a nonempty database password")
	}
	config.Password = password
	return config, nil
}

func (config databaseSettings) log(logger *log.Logger) {
	logger.Print("env EDGE_DB_HOST=" + config.Host)
	logger.Print("env EDGE_DB_NAME=" + config.Name)
	logger.Print("env EDGE_DB_PASSWORD=[redacted]")
}
