# Additional Security Notes

## Baseline Systemd settings
`netfoil` is run without capabilities, as a `DynamicUser` (i.e. generated just for this program), with `NoNewPrivileges`
and most of the security hardening features of Systemd enabled.

Network and LSMs (e.g. AppArmor) are specifically left to be set outside the systemd config.

## Firewall
*TODO*: describe how to use cgroup `netfoil.slice` to allow DoH for netfoil and block fallback attempts.

## AppArmor
See [/packaging/apparmor/netfoil](/packaging/apparmor/netfoil) for the policy.

## Seccomp
To reduce the maintenance burden and the chance of breaking things
the default seccomp profile is broader than necessary.

See the commented out `SystemCallFilter=` in [/packaging/systemd/netfoil.service](/packaging/systemd/netfoil.service) for a much smaller set.

## Mounts
The `mounts` list has been made as minimal as possible while having a reasonable Systemd config. From the kernel perspective it
could still be smaller.

## Speculative execution
Assuming you have not mitigated speculation attacks systemd wide, you can isolate `netfoil` with the following techniques.

### Protect the system from `netfoil`

You can run `netfoil` on its own CPU core(s), not sharing L2/L3 cache and SMT to mitigate some speculative execution attacks.
[/packaging/systemd/netfoil.slice](/packaging/systemd/netfoil.slice) contains `AllowedCPUs` that can be configured for your system.
Select all cores that share L2/L3 and SMT, then set the inverse in `/etc/systemd/system/system.slice` and
`/etc/systemd/system/user.slice`.

Run `netfoil` with `--disable-speculation` to further mitigate speculation attacks, including Spectre v2 type attacks.

### Protect `netfoil` from the system
Build `netfoil` with the `-spectre=all` flags specified in [/build.sh](/build.sh)