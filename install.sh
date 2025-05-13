#!/bin/bash

# AppArmor
#cp packaging/apparmor/netfoil /etc/apparmor.d/netfoil
#apparmor_parser -r /etc/apparmor.d/netfoil

systemctl stop netfoil.socket --quiet
systemctl stop netfoil --quiet

sleep .2
cp packaging/systemd/netfoil.socket /usr/lib/systemd/system/netfoil.socket
cp packaging/systemd/netfoil.service /usr/lib/systemd/system/netfoil.service
cp packaging/systemd/netfoil.slice /usr/lib/systemd/system/netfoil.slice

cp netfoil /usr/sbin/netfoil
systemctl daemon-reload
systemctl start netfoil.socket
systemctl start netfoil.service
