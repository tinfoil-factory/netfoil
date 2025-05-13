#!/bin/bash

GOOS=linux GOARCH=amd64 GO111MODULE=on CGO_ENABLED=0 go build -trimpath -o netfoil cmd/netfoil/main.go

# Turn on all spectre mitigations https://go.dev/wiki/Spectre
# This is mainly to protect against other programs snooping, which is less relevant for netfoil since in the common case it will handle public DNS data
#GOOS=linux GOARCH=amd64 GO111MODULE=on CGO_ENABLED=0 go build -trimpath -gcflags=all=-spectre=all -asmflags=all=-spectre=all -o netfoil