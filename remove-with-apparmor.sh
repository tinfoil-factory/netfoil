#!/bin/bash

systemctl stop netfoil.socket
systemctl stop netfoil.service
systemctl stop netfoil.slice
systemctl disable netfoil.socket
systemctl disable netfoil.service
systemctl disable netfoil.slice

# AppArmor
apparmor_parser -R /etc/apparmor.d/netfoil
rm -f /etc/apparmor.d/netfoil

rm -f /usr/lib/systemd/system/netfoil.socket
rm -f /usr/lib/systemd/system/netfoil.service
rm -f /usr/lib/systemd/system/netfoil.slice
rm -f /usr/sbin/netfoil

systemctl daemon-reload
