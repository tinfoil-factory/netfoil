# netfoil config

## Command Line

### --ip \<ip>
Set the IP to listen on. When running with systemd, [/packaging/systemd/netfoil.socket](/packaging/systemd/netfoil.socket) is used instead.

 - *Required*: no
 - *Default*: `127.0.0.1`

### --port \<port>
Set the port to listen on. When running with systemd, [/packaging/systemd/netfoil.socket](/packaging/systemd/netfoil.socket) is used instead.

 - *Required*: no
 - *Default*: `53`

### --config-directory \<path>
Set the path to look for the config (`<CONFIG DIRECTORY>`).

 - *Required*: no
 - *Default*: `/etc/netfoil`

### --disable-speculation
Disables speculative execution using the Linux system call `prctl`.

 - *Required*: no
 - *Default*: `false`

### --pin-certificate-authority
Uses the specified file as the Certificate Authority for DoH.

- *Required*: no
- *Default*: not set
- *Example*: `/etc/pki/ca-trust/extracted/pem/directory-hash/DigiCert_Global_Root_G2.pem`

## Config file
Located in `<CONFIG DIRECTORY>/config`.

### DoHURL=
Full URL to perform DoH requests.

 - *Required*: yes
 - *Example*: `DoHURL=https://security.cloudflare-dns.com/dns-query`

### DoHIPs=
List of IPs of the `DoHURL=`.

 - *Required*: yes
 - *Example*: `DoHIPs=1.1.1.2,1.0.0.2`

### LogAllowed=
Log each allowed request on a single line: `<allow/deny>|<domain>|<record type>`.

 - *Required*: no
 - *Default*: `true`
 - *Example*: `LogAllowed=false`

### LogDenied=
Log each allowed request on a single line: `<allow/deny>|<domain>|<record type>`.

 - *Required*: no
 - *Default*: `true`
 - *Example*: `LogDenied=false`

### LogLevel=
Set log level.

 - *Required*: no
 - *Default*: `info`
 - *Supported*: `info`, `debug`
 - *Example*: `LogLevel=debug`

### MinTTL=
In seconds. If a TTL in an answer is lower than this number, it will be replaced by this instead.

 - *Required*: no
 - *Default*: `0`
 - *Example*: `MinTTL=10`

### MaxTTL=
In seconds. If a TTL in an answer is larger than this number, it will be replaced by this instead.

- *Required*: no
- *Default*: `4294967295` (uint32 max)
- *Example*: `MaxTTL=60`

### DenyPunycode=
Boolean. If any request containing [punycode](https://en.wikipedia.org/wiki/Punycode) should be denied. Punycode is used to encode non-ASCII characters, e.g.
`münchen.de` is encoded `xn--Mnchen-3ya.com`. The non-ASCII characters could be used in typosquatting attacks.

 - *Required*: no
 - *Default*: `false`
 - *Example*: `DenyPunycode=true`

### RemoveECH=
Boolean. If the ECH part of HTTPS responses should be removed, i.e. omitted from what is returned to the client.

- *Required*: no
- *Default*: `false`
- *Example*: `RemoveECH=true`

### PinResponseDomain=
Boolean. Whether to pin responses domain based on the config file `pin.response-domain`.

- *Required*: no
- *Default*: `false`
- *Example*: `PinResponseDomain=true`

## Config directory
The default config is located in [/packaging/config](/packaging/config). It should be placed in `<CONFIG DIRECTORY>`.

Most of these are in a allow/deny pairs. For e.g. a TLD to be accepted it needs to be 
in the `allow.tld` but not in `deny.tld`. I.e. deny always takes precedence, and
if the value is not in allow, it will also be denied.

### config
Specified in the section above.

### allow.exact / deny.exact
List of domains, one per line.

Examples: `example.com` and `subdomain.example.com`.

### allow.ipv4 / deny.ipv4
List of IPv4 ranges, one per line.

Examples: `127.0.0.1/32`, `10.0.0.0/16`.

### allow.ipv6 / deny.ipv6
List of IPv6 ranges, one per line.

Examples: `::/128`, `100::/64`.

### allow.suffix / deny.suffix
List of domain suffixes, one per line.

Example: `.example.com`

### allow.tld / deny.tld
List of TLDs, one per line.

Example: `.com`

### pin.response-domain
List of allowed CNAME request/response pairs.

Example: `example.com:cdn.example.com`

### known-reserved.ipv4
List of known reserved IPv4 ranges. These are currently only here to be copy/pasted into `allow.ipv4` and `deny.ipv4`.

### known-reserved.ipv6
List of known reserved IPv6 ranges. These are currently only here to be copy/pasted into `allow.ipv6` and `deny.ipv6`.

### known.tld
List of all known TLDs. These are used to check that a TLD is valid before it is checked against the other rules.
When new TLDs are added after the software has been released or you use custom TLDs, they need to be added to this list 
before they can be used in other rules.
