#!/bin/bash
mkdir -p pcaps
ifs=($(ip link | grep -oP 's2-eth[0-9]+(?=@if)'))
tshark -f 'tcp port 80' ${ifs[@]/#/-i } -w pcaps/s2-h.pcapng
