# netfoil

A work in progress DNS proxy/filter.

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

## Config
See [docs/config.md](docs/config.md)

## Features
 - general DoH ([RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484)) support (Cloudflare, Google, etc.)
 - support for A, AAAA, and HTTPS questions
 - support for A, AAAA, HTTPS (including ECH), and CNAME answers
 - allow/deny based on exact, suffix, and TLD
 - deny based on punycode, invalid label, invalid TLD
 - deny IPv4 and IPv6 ranges (e.g. deny reserved IPs to avoid DNS rebinding attacks)
 - both questions and answers are filtered
 - hardened Systemd config (no capabilities, NoNewPrivileges, Seccomp, DynamicUser, ++)
 - Apparmor config
 - Config to mitigate speculative execution
 - run in a separate `netfoil.slice` cgroup, to allow blocking fallback attempts to other DNS resolvers
 - caching of DoH responses
 - configure min/max TTL
 - optional removal of ECH from HTTPS answers
