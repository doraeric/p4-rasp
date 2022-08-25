#!/bin/bash
mkdir -p pcaps
tshark -f 'tcp portrange 50001-50010' -i lo -w pcaps/lo.pcapng
