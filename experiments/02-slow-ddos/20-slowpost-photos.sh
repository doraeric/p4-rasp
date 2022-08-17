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

monitor_time=420
attack_time=180

# read  -n 1 -p "Input:" userinput
pushd ../../monitor-agent >/dev/null
sudo node index.mjs -o "$CWD/num_sockets.tsv" --timeout $monitor_time 2>/tmp/monitor-stderr.log >/tmp/monitor.log &
popd >/dev/null
sleep 2 # wait monitor to setup

# client x6
for i in {2..7}; do
    sudo nsenter -a -t ${mn_host_pid[$i]} timeout $monitor_time /bin/bash -l /cwd/30-post-photos.sh h$i >/tmp/slow-h${i}.log 2>&1 &
done

# attacker x4
for i in {8..11}; do
    sudo nsenter -a -t ${mn_host_pid[$i]} slowhttptest -u http://10.0.1.1 -B -c 40 -r 4 -l $attack_time -i 1 >/tmp/slow-h${i}.log &
done

# https://stackoverflow.com/questions/356100/
for job in `jobs -p`; do
    echo wait pid $job
    wait $job || let "FAIL+=1"
done

date +"%Y-%m-%dT%T.%3N"
