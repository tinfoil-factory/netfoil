#!/bin/bash

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

systemctl stop "netfoil-dns-$instance.socket" --quiet
systemctl stop "netfoil-dns@$instance.service" --quiet

set -e

# AppArmor
cp packaging/apparmor/netfoil-dns /etc/apparmor.d/netfoil-dns
apparmor_parser -r /etc/apparmor.d/netfoil-dns

sleep .2
cp "packaging/systemd/netfoil-dns@.service" "/usr/lib/systemd/system/netfoil-dns@.service"
cp "packaging/systemd/netfoil-dns-$instance.socket" "/usr/lib/systemd/system/netfoil-dns-$instance.socket"
cp "packaging/systemd/netfoil_$instance-dns.slice" "/usr/lib/systemd/system/netfoil_$instance-dns.slice"

cp netfoil-dns /usr/sbin/netfoil-dns
systemctl daemon-reload
systemctl start "netfoil-dns-$instance.socket"
systemctl start "netfoil-dns@$instance.service"

systemctl enable "netfoil-dns@$instance.service"
