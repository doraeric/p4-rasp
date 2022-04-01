#!/bin/bash
slowhttptest -u http://10.0.1.1/posts -c 40000 -B -i 50 -r 50 -s 16384 -t POST -x 10 -p 10 -g -o /cwd/log/slow_body
