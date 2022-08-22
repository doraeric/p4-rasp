#!/bin/bash
set -e
export PATH="${PATH}:/bin"
count=$1
timeout=$2
if [[ $# -lt 2 ]]; then
    echo "usage: $0 <count> <timout>"
    exit -1
fi

start_time=$(date +%s)
stop_time=$((start_time + timeout))
conn_duration=9
rate=10

# register ip
curl -s http://10.0.1.1 > /dev/null

while [[ $((`date +%s` + conn_duration + sleep_time)) -le $stop_time ]]; do
    slowhttptest -u http://10.0.1.1/api/gps-locations -B -c $count -r $rate -l $conn_duration -i $((conn_duration + 1))
done
remain_time=$((stop_time - `date +%s`))
if [[ $remain_time -gt $conn_duration ]]; then
    remain_time=$conn_duration
fi
if [[ $remain_time -gt 0 ]]; then
    slowhttptest -u http://10.0.1.1/api/gps-locations -B -c $count -r $rate -l $conn_duration -i $((conn_duration + 1))
fi
