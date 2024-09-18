exec_package = cmd/*.go
build_flags = -ldflags "-w -s"
exec_file = zerossl-ip-cert

linux_amd64_dist = dist


.PHONY: release
.DEFAULT_GOAL := release

release: linux-amd64

linux-amd64:
	mkdir -p $(linux_amd64_dist)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(build_flags) -o $(linux_amd64_dist)/$(exec_file) $(exec_package)