package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/tinfoil-factory/netfoil/dns"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const usage = `SYNOPSIS
    netfoil [OPTIONS]

OPTIONS
        --ip
            IP to listen on (default: 127.0.0.1).

        --port
            UDP port to listen on (default: 53).

        --config-directory
			Config directory (default: /etc/netfoil).

        --disable-speculation
			Disable speculative execution (default: false).

        --filter-system-calls
            Apply seccomp filter for system calls (default: false, only supported on x86_64).

        --help, -h
			Print the help message.

Example
    $ netfoil --ip 127.0.0.1 --port 53 --config-directory /etc/netfoil`

func main() {
	options, err := processInput()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	err = disableSpeculation(options.DisableSpeculation)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	config, err := dns.ReadConfigFile(options.ConfigDirectory)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	configureLogger(config)

	conn, err := systemdSocketListener()
	if err != nil {
		println(err.Error())
	}

	if conn == nil {
		conn, err = bindService(options.IP, options.Port)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	}
	defer conn.Close()

	policy, err := dns.NewPolicy(options.ConfigDirectory, config.DenyPunycode)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	// Apply late for a shorter allowlist
	err = applySystemCallFilter(options.FilterSystemCalls)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	err = dns.Server(conn, config, policy)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

func disableSpeculation(disable bool) error {
	if disable {
		_, _, err := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_STORE_BYPASS), uintptr(unix.PR_SPEC_FORCE_DISABLE), 0, 0, 0)
		if err != 0 {
			return fmt.Errorf("error disabling store bypass speculation: %s\n", err)
		}

		_, _, err = syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_INDIRECT_BRANCH), uintptr(unix.PR_SPEC_FORCE_DISABLE), 0, 0, 0)
		if err != 0 {
			return fmt.Errorf("error disabling store bypass speculation: %s\n", err)
		}

		/*
			err = unix.Prctl(unix.PR_SET_SPECULATION_CTRL, uintptr(unix.PR_SPEC_L1D_FLUSH), uintptr(unix.PR_SPEC_DISABLE), 0, 0)
			if err != nil {
				return fmt.Errorf("error setting L1D flush: %w\n", err)
			}
		*/
	}

	return nil
}

func applySystemCallFilter(filter bool) error {
	if filter {
		// NoNewPrivs must be applied before the seccomp filter
		_, _, errInt := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, uintptr(1), 0, 0, 0, 0)
		if errInt != 0 {
			return fmt.Errorf("error setting NoNewPrivs: %s\n", errInt)
		}

		allowedSyscalls := []uint32{
			// @default
			//unix.SYS_ARCH_PRCTL,
			unix.SYS_RT_SIGRETURN,
			unix.SYS_SCHED_GETAFFINITY,
			unix.SYS_SCHED_YIELD,
			//unix.SYS_EXECVE,
			unix.SYS_FUTEX,
			unix.SYS_GETPID,
			unix.SYS_GETRANDOM,
			//unix.SYS_GETRLIMIT,
			unix.SYS_GETTID,
			unix.SYS_MMAP,
			unix.SYS_NANOSLEEP,
			unix.SYS_EXIT,
			unix.SYS_EXIT_GROUP,
			// @sandbox
			//unix.SYS_SECCOMP,

			// @basic-io
			unix.SYS_CLOSE,
			unix.SYS_READ,
			unix.SYS_WRITE,
			unix.SYS_PREAD64,

			// @file-system
			unix.SYS_FCNTL,
			unix.SYS_FSTAT,
			unix.SYS_GETDENTS64,
			unix.SYS_OPENAT,
			unix.SYS_READLINKAT,

			// @network-io
			unix.SYS_CONNECT,
			unix.SYS_GETPEERNAME,
			unix.SYS_GETSOCKNAME,
			unix.SYS_GETSOCKOPT,
			unix.SYS_RECVFROM,
			unix.SYS_SENDTO,
			unix.SYS_SETSOCKOPT,
			unix.SYS_SOCKET,

			// @signal
			unix.SYS_RT_SIGRETURN,
			unix.SYS_RT_SIGPROCMASK,
			unix.SYS_SIGALTSTACK,

			// @process
			unix.SYS_CLONE,
			//unix.SYS_PRCTL,
			unix.SYS_TGKILL,

			// @io-event
			//unix.SYS_EPOLL_CREATE1,
			unix.SYS_EPOLL_CTL,
			unix.SYS_EPOLL_PWAIT,
			//unix.SYS_EVENTFD2,

			// @system-service
			unix.SYS_MADVISE,

			// @resources
			//unix.SYS_SETRLIMIT,
		}

		instructions := make([]bpf.Instruction, 0)

		syscallOffset := uint32(0)
		archOffset := uint32(4)
		intSize := 4

		instructions = append(instructions, bpf.LoadAbsolute{Off: archOffset, Size: intSize})
		instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.AUDIT_ARCH_X86_64, SkipTrue: 1})
		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		instructions = append(instructions, bpf.LoadAbsolute{Off: syscallOffset, Size: intSize})
		for _, s := range allowedSyscalls {
			instructions = append(instructions, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: s, SkipTrue: 1})
			instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_ALLOW)})
		}

		instructions = append(instructions, bpf.RetConstant{Val: uint32(unix.SECCOMP_RET_KILL_PROCESS)})

		program, err := createSeccompProgram(instructions)
		if err != nil {
			return err
		}

		_, _, errInt = syscall.AllThreadsSyscall6(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(program)), 0, 0, 0)
		if errInt != 0 {
			return fmt.Errorf("error setting seccomp: %d", errInt)
		}
	}

	return nil
}

func createSeccompProgram(instructions []bpf.Instruction) (*syscall.SockFprog, error) {
	rawInstructions, err := bpf.Assemble(instructions)
	if err != nil {
		return nil, err
	}

	filter := make([]syscall.SockFilter, 0)
	for _, instruction := range rawInstructions {
		filter = append(filter, syscall.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		})
	}

	program := &syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	return program, nil
}

func configureLogger(config *dns.Config) {
	opts := &slog.HandlerOptions{
		Level: config.LogLevel,
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, opts))
	slog.SetDefault(logger)
}

func systemdSocketListener() (*net.UDPConn, error) {
	if _, ok := os.LookupEnv("LISTEN_FDS"); ok {
		f := os.NewFile(uintptr(3), "netfoil.socket")

		conn, err := net.FileConn(f)
		if err != nil {
			return nil, err
		}

		return conn.(*net.UDPConn), nil
	}

	return nil, fmt.Errorf("systemd socket listener not configured")
}

type Options struct {
	IP                 net.IP
	Port               int
	ConfigDirectory    string
	DisableSpeculation bool
	FilterSystemCalls  bool
}

func processInput() (*Options, error) {
	flags := flag.NewFlagSet("all", flag.ExitOnError)
	var help, h, disableSpeculation, filterSystemCalls bool
	var configPath, ipString string
	var portInt int
	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&h, "h", false, "")
	flags.BoolVar(&disableSpeculation, "disable-speculation", false, "")
	flags.BoolVar(&filterSystemCalls, "filter-system-calls", false, "")
	flags.IntVar(&portInt, "port", 53, "")
	flags.StringVar(&ipString, "ip", "127.0.0.1", "")
	flags.StringVar(&configPath, "config-directory", "/etc/netfoil", "")

	err := flags.Parse(os.Args[1:])
	if err != nil || help || h {
		fmt.Println(usage)
		os.Exit(1)
	}

	if portInt < 0 || portInt > 65535 {
		return nil, fmt.Errorf("invalid port %d", portInt)
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	// TODO input validate configPath

	return &Options{
		IP:                 ip,
		Port:               portInt,
		ConfigDirectory:    configPath,
		DisableSpeculation: disableSpeculation,
	}, nil
}

func bindService(ip net.IP, port int) (*net.UDPConn, error) {
	addr := net.UDPAddr{
		Port: port,
		IP:   ip,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
