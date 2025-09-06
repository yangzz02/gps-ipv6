#!/bin/bash

src=$(curl -s https://api-ipv6.ip.sb/ip -A Mozilla)
m=$(ip link show $1 | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
g=$(ip -6 neigh show | grep router | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)

sudo ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -s $src -j DROP

sudo xmap $2 -p $3 -M tcp_syn -R 5000 -O json --output-filter="success = 1 && repeat = 0" -f "saddr,daddr,sport,dport,seqnum,acknum,window" -I $4 | lzr --handshakes http,tls --sendInterface ens33 --gatewayMac $g --f=$5 -IPv6 -onlyDataRecord | zgrab2 multiple -c etc/all.ini -o $6

sudo ip6tables -F


