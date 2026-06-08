#!/bin/bash

set -e

CONFIG_DIRECTORY=/etc/netfoil/
mkdir -p "${CONFIG_DIRECTORY}"
cp --update=none packaging/config/* "${CONFIG_DIRECTORY}"
