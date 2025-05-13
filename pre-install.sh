#!/bin/bash

CONFIG_DIRECTORY=/etc/netfoil/
mkdir -p "${CONFIG_DIRECTORY}"
cp packaging/config/* "${CONFIG_DIRECTORY}"
