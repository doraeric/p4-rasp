#!/bin/bash
s=0
f=0
for i in {01..10}; do
    for j in {2..7}; do
        diff /opt/landscape-photo/$i.jpg /opt/pad.js/h$j/$i.jpg > /dev/null
        if [ $? -eq 0 ]; then
            s=$(($s + 1))
        else
            f=$(($f + 1))
        fi
    done
done
echo success/total = $s / $(($s + $f))

each_size=$(ls -l /opt/landscape-photo/*.jpg | awk '{print $5}' | awk '{s+=$1} END {print s}')
received=$(ls -l /opt/pad.js/h*/*.jpg | awk '{print $5}' | awk '{s+=$1} END {print s}')
echo -e "files\tBytes"
echo -e "sum\t$(echo "$each_size * 6" | bc)"
echo -e "recv\t$received"
