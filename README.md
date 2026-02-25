# xDS API

[![GoDoc](https://pkg.go.dev/badge/github.com/dubbo-kubernetes/xds-api.svg)](https://pkg.go.dev/github.com/dubbo-kubernetes/xds-api)

This repository contains the xDS API defined for the Dubbo control plane implementation.

## Generate

Install protoc plugin:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

Generate pb.go files:

```bash
protoc -I. --go_out=. --go_opt=paths=source_relative $(find . -name "*.proto")
```

