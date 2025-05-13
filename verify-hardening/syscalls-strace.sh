strace -f -o strace-out ./netfoil --port 5353 --config-directory config
cat strace-out | cut -d " " -f2 | cut -d "(" -f1 | sort | uniq  > strace-syscalls
