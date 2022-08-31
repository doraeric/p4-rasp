#!/bin/bash
set -e
systemctl status auditd.service >/dev/null || systemctl status auditd.service

sudo id
date +"%Y-%m-%dT%T.%3N"
CWD=`pwd`
mn_host_pid=()
for i in {1..11}; do
    mn_host_pid[$i]=`pgrep -f "is mininet:h$i\b"`
done

monitor_time=300
attack_time=180

# read  -n 1 -p "Input:" userinput
pushd ../../monitor-agent >/dev/null
sudo node index.mjs -o "$CWD/num_sockets.tsv" --timeout $monitor_time 2>/tmp/monitor-stderr.log >/tmp/monitor.log &
popd >/dev/null
sleep 2 # wait monitor to setup

# client x6
for i in {2..7}; do
    sudo nsenter -a -t ${mn_host_pid[$i]} python3 /cwd/gps_client.py http://10.0.1.1/api/gps-locations \
        --desc h$i --timeout $monitor_time >/tmp/slow-h${i}.log 2>&1 &
done

# attacker x4
for i in {8..11}; do
    sudo nsenter -a -t ${mn_host_pid[$i]} slowhttptest -u http://10.0.1.1 -B -c 50 -r 2 -l $attack_time -i 1 >/tmp/slow-h${i}.log &
done

# https://stackoverflow.com/questions/356100/
for job in `jobs -p`; do
    echo wait pid $job
    wait $job || let "FAIL+=1"
done

# calculate results
total_success=0
total_fail=0
for i in {2..7}; do
    vars=$(tail -n2 /tmp/slow-h$i.log | tr -s ' ' | rev | cut -f 1-3 -d ' ' | rev | sed 's/ //g')
    eval $vars
    total_success=$((total_success + success))
    total_fail=$((total_fail + fail))
done
echo total_success=$total_success
echo total_fail=$total_fail
success_rate=$(echo "print($total_success / ($total_success + $total_fail))" | python3)
echo success_rate=$success_rate

date +"%Y-%m-%dT%T.%3N"
