module github.com/tinfoil-factory/netfoil

go 1.26.0

toolchain go1.27.3

godebug (
	multipathtcp=0
	// This is required to avoid the associated SYS_PRCTL call for systems where CONFIG_ANON_VMA_NAME is set
	decoratemappings=0
)

require (
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
)
