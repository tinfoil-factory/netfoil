module github.com/tinfoil-factory/netfoil

go 1.26.0

toolchain go1.27.3

// This is required to avoid the associated SYS_PRCTL call for systems where CONFIG_ANON_VMA_NAME is set
godebug (
	decoratemappings=0
	multipathtcp=0
)

require (
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
)
