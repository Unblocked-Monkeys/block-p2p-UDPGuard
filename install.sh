#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" >&2
   exit 1
fi

apt update &&\
  apt install -y iptables ipset ipcalc rsyslog grep coreutils &&\
  cp block-p2p.sh /usr/bin/block-p2p.sh &&\
  cp block-p2p.service /etc/systemd/system/block-p2p.service &&\
  chmod +x /usr/bin/block-p2p.sh &&\
  systemctl daemon-reload &&\
  systemctl enable --now block-p2p.service &&\
  echo "Installation complete. Service working on a background"