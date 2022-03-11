SHELL=/bin/bash

UID := $(shell id -u)
GID := $(shell id -g)
PWD := $(shell pwd)

P4C=docker run --rm \
   -u ${UID}:${GID} \
   -v "${PWD}:/cwd" \
   -w /cwd \
   opennetworking/p4c:stable \
   p4c-bm2-ss

P4FLAGS=--arch v1model

.PHONY: all env

all:
	mkdir -p build
	$(P4C) $(P4FLAGS) \
		-o build/bmv2.json --p4runtime-files build/p4info.txt src/basic.p4

env:
	@# eval `make env`
	$(eval P4BIN := $(shell readlink -f build/bmv2.json))
	$(eval P4INFO := $(shell readlink -f build/p4info.txt))
	@echo export P4INFO=\"${P4INFO}\" P4BIN=\"${P4BIN}\"
