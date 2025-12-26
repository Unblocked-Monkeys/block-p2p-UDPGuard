#!/bin/bash

IPSET_NAME="torrent_block"

if ipset list -n | grep -qw "$IPSET_NAME"; then
  echo "Clearing ipset!"
  ipset flush "$IPSET_NAME"
fi