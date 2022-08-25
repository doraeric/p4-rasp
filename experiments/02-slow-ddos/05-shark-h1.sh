#!/bin/bash
h1_pid=`pgrep -f "is mininet:h1\b"`
output=pcaps/h1.pcapng
mkdir -p pcaps
touch "$output"
chmod o=rw "$output"
sudo nsenter -n -t ${h1_pid} tshark -f 'tcp port 80' -i h1-eth0 -w "$output"
