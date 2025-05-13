TARGET_PID=`systemctl show netfoil | grep ^MainPID | cut -d "=" -f2`

assertEqual () {
	DIFF=`diff "$1" "$2"`
	if [ ! -z "${DIFF}" ]
	then
		echo "$3"
		exit 1
	fi
}

assertNotEqual () {
	DIFF=`diff "$1" "$2"`
	if [ -z "${DIFF}" ]
	then
		echo "$3"
		exit 1
	fi
}

assertNotInGlobalNamespace () {
	TYPE=$1
	sudo readlink "/proc/1/ns/${TYPE}" > "ns-${TYPE}-root"
	sudo readlink "/proc/${TARGET_PID}/ns/${TYPE}" > "ns-${TYPE}-actual"
	assertNotEqual "ns-${TYPE}-root" "ns-${TYPE}-actual" "global namespace of type ${TYPE}"
}

assertEmptyDir () {
	CONTENTS=`sudo ls -A /proc/$TARGET_PID/root/$1`
	if [ ! -z "${CONTENTS}" ]
	then
		echo "directory $1 not empty"
		exit 1
	fi
}

assertSingleEntryDir () {
	CONTENTS=`sudo ls -A /proc/$TARGET_PID/root/$1`
	if [ "${CONTENTS}" != "${2}" ]
	then
		echo "directory $1 contains $CONTENTS"
		exit 1
	fi
}

# Assert settings in status file
cat "/proc/1/status" | grep ^Uid: > uid-root
cat "/proc/${TARGET_PID}/status" | grep ^Uid: > uid-actual
assertNotEqual uid-root uid-actual "UID 0"

cat "/proc/1/status" | grep ^Gid: > gid-root
cat "/proc/${TARGET_PID}/status" | grep ^Gid: > gid-actual
assertNotEqual gid-root gid-actual "GID 0"

cat "/proc/${TARGET_PID}/status" | grep ^NoNewPrivs: > nonewprivs-actual
assertEqual nonewprivs-expected nonewprivs-actual "Wrong NoNewPrivs"

cat "/proc/${TARGET_PID}/status" | grep ^Seccomp: > seccomp-actual
assertEqual seccomp-expected seccomp-actual "Wrong Seccomp"

# capsh --decode=0000000000000400
# 0x0000000000000400=cap_net_bind_service
cat /proc/$TARGET_PID/status | grep ^Cap > caps-actual
assertEqual caps-expected caps-actual "Wrong capabilites"

# Assert namespaces
assertNotInGlobalNamespace mnt
assertNotInGlobalNamespace ipc
assertNotInGlobalNamespace uts

# Assert expected directory and file structure
sudo ls -A /proc/$TARGET_PID/root/ > root-actual
assertEqual root-expected root-actual "Wrong contents in /"

#assertSingleEntryDir dev mqueue

sudo ls -A /proc/$TARGET_PID/root/etc/ > etc-actual
assertEqual etc-expected etc-actual "Wrong contents in /dev/"

# proc
# run
# sys
assertEmptyDir tmp

assertSingleEntryDir usr sbin
assertSingleEntryDir usr/sbin netfoil

assertSingleEntryDir var tmp
assertEmptyDir var/tmp

# Assert AppArmor
cat /proc/$TARGET_PID/attr/current > apparmor-actual
assertEqual apparmor-expected apparmor-actual "Wrong AppArmor"

# Assert cgroups
cat /sys/fs/cgroup/netfoil.slice/netfoil.service/cpu.max > cpu.max-actual
assertEqual cpu.max-expected cpu.max-actual "Wrong cpu.max"

cat /sys/fs/cgroup/netfoil.slice/netfoil.service/memory.max > memory.max-actual
assertEqual memory.max-expected memory.max-actual "Wrong memory.max"

cat /sys/fs/cgroup/netfoil.slice/netfoil.service/pids.max > pids.max-actual
assertEqual pids.max-expected pids.max-actual "Wrong pids.max"
