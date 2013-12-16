#!/usr/bin/env bash

set -evx

usage() {
cat <<EOF
   Usage:
        check_certificate_chain.sh [hostname/ip] [port]

EOF
exit 1
}

connection_info() {
	local server=$1
	local port=$2
	local cmd="$(timeout 2 openssl s_client -connect ${server}:${port} -verify 100 &>1)"
	if [[ $cmd =~ /errorno=22/ ]]; then
		usage	
	fi
	echo $cmd
}

# MAIN
[ $# -lt 2 ] && usage

connection_info $1 $2


