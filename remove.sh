#!/bin/bash

systemctl stop netfoil.socket
systemctl stop netfoil.service
systemctl stop netfoil.slice
systemctl disable netfoil.socket
systemctl disable netfoil.service
systemctl disable netfoil.slice

# AppArmor
#apparmor_parser -R /etc/apparmor.d/netfoil
#rm /etc/apparmor.d/netfoil

rm /usr/lib/systemd/system/netfoil.socket
rm /usr/lib/systemd/system/netfoil.service
rm /usr/lib/systemd/system/netfoil.slice
rm /usr/sbin/netfoil

systemctl daemon-reload
