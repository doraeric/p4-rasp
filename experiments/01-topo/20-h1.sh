#!/bin/bash

# setup
ip link set h1-eth0 promisc on
echo 'alert tcp any any -> any 80 (content:"GET"; http_method; sid:3000001)' > /etc/snort/rules/myrule.rules
# include $RULE_PATH/yourrule.rules > /etc/snort/snort.conf

# log - snort
# snort -d -l /var/log/snort/ -h 10.0.1.1/24 -A fast -c /etc/snort/snort.conf
# mv /var/log/snort/alert log

# log - tshark
# tshark -i h1-eth0 -w /root/h1-eth0.pcap
# mv /root/h1-eth0.pcap log

# request
# for i in {1..1001}; do curl 10.0.1.1; sleep 1; done
