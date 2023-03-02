#!/bin/sh

export RAC__DEVICE__SSH_HOST_PORT=$(/sbin/ip route|awk '/default/ { print $3 }'):22
export RAC__TORIZON__URL=$(cat /opt/rac/device-files/gateway.url)/ras

cd /opt/rac/

if [[ "$DEBUG" == "true" ]]; then
    export RUST_LOG="rac=debug"
fi

export CONFIG_FILE="client-docker.toml"

exec ./rac
