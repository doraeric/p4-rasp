#!/bin/bash
for i in {1..10}; do
    curl 10.0.1.1 >/dev/null
    date +"%Y-%m-%dT%T.%3N"
    sleep 1
done
