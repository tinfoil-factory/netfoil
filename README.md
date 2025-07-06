# netfoil

netfoil is a minimal, allowlist based, DNS proxy written in Go.
DNS filtering, especially with a strict allowlist, can be a powerful way to reduce attack surface.
netfoil was created to enable this filtering on the client side, while only supporting DNS over HTTPS (DoH) externally.
netfoil is designed to be small enough to be auditable, and hardened enough to not be the weak link.

*Please note:*
 - care must be taken when integrating netfoil in order to block fallback attempts using other resolvers.
 - DNSSEC is currently not supported.

## Features
- general DoH ([RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484)) support (Cloudflare, Google, etc.)
- support for A, AAAA, and HTTPS questions
- support for A, AAAA, HTTPS (including ECH), and CNAME answers
- allow/deny based on exact, suffix, and TLD
- deny based on punycode, invalid label, invalid TLD
- deny IPv4 and IPv6 ranges (e.g. deny reserved IPs to avoid DNS rebinding attacks, or drop all IPv4 or IPv6 results)
- both questions and answers are filtered
- hardened systemd config (no capabilities, NoNewPrivileges, Seccomp, DynamicUser, ++)
- AppArmor config
- config to mitigate speculative execution
- run in a separate `netfoil.slice` cgroup, to allow blocking fallback attempts to other DNS resolvers
- caching of DoH responses
- configure min/max TTL
- optional removal of ECH from HTTPS answers (e.g. to enable SNI inspection on the network)

## Config
See [docs/config.md](docs/config.md)

## Try it out
Build/start
```
./build.sh
./netfoil --port 5353 --config-directory packaging/config
```

Perform query
```
dig @127.0.0.1 -p 5353 example.com
```

## Install
*TODO*: better packaging.

Copy `config` directory to `/etc/netfoil`
```
./pre-install.sh
```

Set up Systemd service and AppArmor
```
./install.sh
```

Edit `/etc/systemd/resolved.conf`
```
DNS=127.0.0.1:53
```
And make sure `DNSSEC=no` and `DNSOverTLS=no`.

## Remove
```
./remove.sh
```
