#!/bin/bash

set -e

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

CONFIG_DIRECTORY="/etc/netfoil/dns/$instance"
mkdir -p "${CONFIG_DIRECTORY}"
cp --update=none packaging/config/* "${CONFIG_DIRECTORY}"
