#!/bin/bash
set -e
export PATH="${PATH}:/bin"
timeout=$1
# output=$2
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <timeout>"
    exit -1
fi

# date +"%T.%3N"
start_ts=$(date +"%s.%3N")
stop_ts=$(echo $start_ts + $timeout | bc)

n=$(netstat -tnp 2>/dev/null | grep 10.0.1.1:80 | wc -l)
now=$(date +"%s.%3N")
echo -e "time\tconn"
echo -e "$now\t$n" # > $output
while [ $(echo "$now < $stop_ts" | bc) -eq 1 ]; do
    sleep .1
    now=$(date +"%s.%3N")
    echo -e "$now\t$n" # >> $output
    n=$(netstat -tnp 2>/dev/null | grep 10.0.1.1:80 | wc -l)
    echo -e "$now\t$n" # >> $output
done
