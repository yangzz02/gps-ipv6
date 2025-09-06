#!/bin/bash

# $1: Network Interface Name
# $2: Port for Scanning
# $3: Input File(IP list)
# $4: lzr output file
# $5: zgrab multiple configuration
# $6: zgrab output file

src=$(curl -s https://api-ipv6.ip.sb/ip -A Mozilla)
m=$(ip link show $1 | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)
g=$(ip -6 neigh show | grep router | grep -o -E "(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})" | head -n 1)

sudo ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -s $src -j DROP

sudo xmap -6 -p $2 -M tcp_syn -R 5000 -O json --output-filter="success = 1 && repeat = 0" -f "saddr,daddr,sport,dport,seqnum,acknum,window" -I $3 | lzr --handshakes wait,http,tls --sendInterface $1 --gatewayMac $g --f=$4 -IPv6 -feedZGrab | zgrab2 multiple -c $5 -o $6

sudo ip6tables -F
