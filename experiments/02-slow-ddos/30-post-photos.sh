#!/bin/bash
set -e
export PATH="${PATH}:/bin"
hostname=$1
if [[ $# -lt 1 ]]; then
    echo "usage: $0 <hostname>"
    exit -1
fi

# register ip
curl http://10.0.1.1 > /dev/null
sleep .1

mkdir -p /opt/pad.js/$hostname
for i in {01..10}; do
    resp=`curl --connect-timeout 30 http://10.0.1.1/$hostname/$i.jpg -F blob=@/opt/landscape-photo/$i.jpg || echo Failed $i`
    if [[ "${resp}" == "UPLOADED" ]]; then
        echo "#$i finished"
    else
        echo "#$i $resp"
    fi
done
