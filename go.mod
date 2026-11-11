module github.com/TeaOSLab/EdgeAPI

go 1.27.0

toolchain go1.27.4

replace github.com/TeaOSLab/EdgeCommon => ../EdgeCommon

require (
	github.com/TeaOSLab/EdgeCommon v0.0.0-00010101000000-000000000000
	github.com/aliyun/alibaba-cloud-sdk-go v1.63.107
	github.com/andybalholm/brotli v1.3.0
	github.com/cespare/xxhash v1.1.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/go-acme/lego/v4 v4.35.2
	github.com/go-sql-driver/mysql v1.10.1
	github.com/iwind/TeaGo v0.0.0-20240508072741-7647e70b7070
	github.com/iwind/gosock v1.0.0
	github.com/miekg/dns v1.1.73
	github.com/mozillazg/go-pinyin v0.21.0
	github.com/pkg/sftp v1.13.12
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.3.211
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod v1.3.131
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.50.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.13-0.20220915233716-71ac16282d12 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20261101121723-be84dd9509a0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/opentracing/opentracing-go v1.2.1-0.20220228012449-10b1cf09e00b // indirect
	github.com/power-devops/perfstat v0.0.0-20260916203055-22a1a467d9f0 // indirect
	github.com/shoenig/go-m1cpu v0.2.4 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)
