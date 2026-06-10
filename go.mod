module github.com/tinfoil-factory/netfoil

go 1.25.0

toolchain go1.25.11

godebug (
  // This is required to avoid the associated SYS_PRCTL call for systems where CONFIG_ANON_VMA_NAME is set
  decoratemappings=0
)

require (
	golang.org/x/net v0.55.0
	golang.org/x/sys v0.45.0
)
