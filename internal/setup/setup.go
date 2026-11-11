package setup

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TeaOSLab/EdgeAPI/internal/configs"
	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeAPI/internal/errors"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpcauth"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/iwind/TeaGo/Tea"
	"github.com/iwind/TeaGo/cmd"
	"github.com/iwind/TeaGo/types"
)

type Setup struct {
	config *Config

	// 要返回的数据
	AdminNodeId     string
	AdminNodeSecret string

	logFp   *os.File
	logPath string
}

func NewSetup(config *Config) *Setup {
	return &Setup{
		config: config,
	}
}

func NewSetupFromCmd() *Setup {
	var args = cmd.ParseArgs(strings.Join(os.Args[1:], " "))

	var config = &Config{}
	for _, arg := range args {
		var index = strings.Index(arg, "=")
		if index <= 0 {
			continue
		}
		var value = arg[index+1:]
		value = strings.Trim(value, "\"'")
		switch arg[:index] {
		case "-api-node-protocol":
			config.APINodeProtocol = value
		case "-api-node-host":
			config.APINodeHost = value
		case "-api-node-port":
			config.APINodePort = types.Int(value)
		}
	}

	var setup = NewSetup(config)

	// log writer
	var tmpDir = os.TempDir()
	if len(tmpDir) > 0 {
		fp, err := openSetupLog(tmpDir)
		if err == nil {
			setup.logFp = fp
			setup.logPath = filepath.Join(tmpDir, "edge-install.log")
		}
	}

	return setup
}

func (this *Setup) Run() error {
	if this.logFp != nil {
		defer func() {
			_ = this.logFp.Close()
			_ = os.Remove(this.logPath)
		}()
	}
	listen, err := setupListenAddress(this.config)
	if err != nil {
		return err
	}

	// 执行SQL
	config, err := configs.LoadDBConfig()
	if err != nil {
		return err
	}
	for _, db := range config.DBs {
		// 可以同时运行多条语句
		if !strings.Contains(db.Dsn, "multiStatements=") {
			if strings.Contains(db.Dsn, "?") {
				db.Dsn += "&multiStatements=true"
			} else {
				db.Dsn += "?multiStatements=true"
			}
		}
	}
	dbConfig, ok := config.DBs[Tea.Env]
	if !ok {
		return errors.New("can not find database config for env '" + Tea.Env + "'")
	}

	var executor = NewSQLExecutor(dbConfig)
	if this.logFp != nil {
		executor.SetLogWriter(this.logFp)
	}
	err = executor.Run(false)
	if err != nil {
		return err
	}

	// Admin节点信息
	var apiTokenDAO = models.NewApiTokenDAO()
	token, err := apiTokenDAO.FindEnabledTokenWithRole(nil, "admin")
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("can not find admin node token, please run the setup again")
	}
	this.AdminNodeId = token.NodeId
	this.AdminNodeSecret = token.Secret

	// 检查API节点
	var dao = models.NewAPINodeDAO()
	apiNodeId, err := dao.FindEnabledAPINodeIdWithAddr(nil, this.config.APINodeProtocol, this.config.APINodeHost, this.config.APINodePort)
	if err != nil {
		return err
	}
	if apiNodeId == 0 {
		addrsJSON, err := json.Marshal([]*serverconfigs.NetworkAddressConfig{listen})
		if err != nil {
			return fmt.Errorf("json encode api node addr failed: %w", err)
		}

		var httpJSON []byte = nil
		var httpsJSON []byte = nil
		if this.config.APINodeProtocol == "http" {
			httpConfig := &serverconfigs.HTTPProtocolConfig{}
			httpConfig.IsOn = true
			httpConfig.Listen = []*serverconfigs.NetworkAddressConfig{listen}
			httpJSON, err = json.Marshal(httpConfig)
			if err != nil {
				return fmt.Errorf("json encode api node http config failed: %w", err)
			}
		}
		if this.config.APINodeProtocol == "https" {
			// TODO 如果在安装过程中开启了HTTPS，需要同时上传SSL证书
			var httpsConfig = &serverconfigs.HTTPSProtocolConfig{}
			httpsConfig.IsOn = true
			httpsConfig.Listen = []*serverconfigs.NetworkAddressConfig{listen}
			httpsJSON, err = json.Marshal(httpsConfig)
			if err != nil {
				return fmt.Errorf("json encode api node https config failed: %w", err)
			}
		}

		// 创建API节点
		nodeId, err := dao.CreateAPINode(nil, "默认API节点", "这是默认创建的第一个API节点", httpJSON, httpsJSON, false, nil, nil, addrsJSON, true)
		if err != nil {
			return fmt.Errorf("create api node in database failed: %w", err)
		}
		apiNodeId = nodeId
	}

	apiNode, err := dao.FindEnabledAPINode(nil, apiNodeId, nil)
	if err != nil {
		return err
	}
	if apiNode == nil {
		return errors.New("apiNode should not be nil")
	}

	// 保存配置
	var apiConfig = &configs.APIConfig{
		NodeId: apiNode.UniqueId,
		Secret: apiNode.Secret,
	}
	err = apiConfig.WriteFile(Tea.ConfigFile("api.yaml"))
	if err != nil {
		return fmt.Errorf("save config failed: %w", err)
	}

	return nil
}

// Publish a newly created 0600 log inode at the Admin reader's stable path.
// Rename replaces a pre-existing symlink/hardlink entry without truncating its
// target; opening that predictable filename with O_TRUNC would follow the link.
func openSetupLog(tmpDir string) (*os.File, error) {
	file, err := os.CreateTemp(tmpDir, ".edge-install-*.log")
	if err != nil {
		return nil, err
	}
	name := file.Name()
	if err := os.Rename(name, filepath.Join(tmpDir, "edge-install.log")); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return nil, err
	}
	return file, nil
}

// The installation address controls both the advertised endpoint and its bind
// address. In particular, a loopback API must not listen on every interface.
func setupListenAddress(config *Config) (*serverconfigs.NetworkAddressConfig, error) {
	if config == nil {
		return nil, errors.New("config should not be nil")
	}
	if config.APINodeProtocol != "http" && config.APINodeProtocol != "https" {
		return nil, errors.New("api node protocol must be http or https")
	}
	if config.APINodeHost == "" {
		return nil, errors.New("api node host should not be empty")
	}
	if config.APINodePort <= 0 || config.APINodePort > 65535 {
		return nil, errors.New("api node port must be between 1 and 65535")
	}
	if config.APINodeProtocol == "http" && !rpcauth.PlaintextAllowed(net.JoinHostPort(config.APINodeHost, strconv.Itoa(config.APINodePort))) {
		return nil, errors.New("plaintext API installation requires explicit migration mode or a literal loopback address in loopback-only mode")
	}
	return &serverconfigs.NetworkAddressConfig{
		Protocol: serverconfigs.Protocol(config.APINodeProtocol), Host: config.APINodeHost,
		PortRange: strconv.Itoa(config.APINodePort),
	}, nil
}
