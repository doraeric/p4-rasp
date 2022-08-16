#!/bin/bash
set -e
systemctl status auditd.service >/dev/null || systemctl status auditd.service

sudo id
CWD=`pwd`
mn_host_pid=()
for i in {1..11}; do
    mn_host_pid[$i]=`pgrep -f "is mininet:h$i\b"`
done

monitor_time=160
attack_time=150

# read  -n 1 -p "Input:" userinput
pushd ../../monitor-agent >/dev/null
sudo node index.mjs -o "$CWD/num_sockets.tsv" --timeout $monitor_time 2>/tmp/monitor-stderr.log >/tmp/monitor.log &
popd >/dev/null
sleep 2 # wait monitor to setup

# client
total_conn=15
for i in {2..7}; do
    if [[ $((i%6)) -lt $((15%6)) ]]; then c=3; else c=2; fi
    # sudo nsenter -a -t ${mn_host_pid[$i]} slowhttptest -u http://10.0.1.1 -H -c 2 -r 2 -l 60 -i 15 2>&1 1>/tmp/slow-h${i}.log &
    sudo nsenter -a -t ${mn_host_pid[$i]} python3 /cwd/slowhttpheader.py \
        -u http://10.0.1.1 -c $c -r 2 -l 9 -i 15 -a $attack_time 1>/tmp/slow-h${i}.log 2>&1 &
done

# attacker
for i in {8..11}; do
    # sudo nsenter -a -t ${mn_host_pid[$i]} slowhttptest -u http://10.0.1.1 -H -c 4 -r 1 -l 30 -i 4 2>&1 1>/tmp/slow-h${i}.log &
    sudo nsenter -a -t ${mn_host_pid[$i]} slowhttptest -u http://10.0.1.1 -H -c 20 -r 4 -l $attack_time -i 1 >/tmp/slow-h${i}.log &
done

# https://stackoverflow.com/questions/356100/
for job in `jobs -p`; do
    echo wait pid $job
    wait $job || let "FAIL+=1"
done
