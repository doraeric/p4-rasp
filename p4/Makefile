SHELL=/bin/bash

UID := $(shell id -u)
GID := $(shell id -g)
PWD := $(shell pwd)
# DOCKER expands to podman or docker, prefer podman if available
DOCKER := $(if $(shell which podman 2>/dev/null),podman,docker)
is_docker := $(filter docker,$(DOCKER))

P4C=$(DOCKER) run --rm \
	$(if $(is_docker),-u ${UID}:${GID},) \
   -v "${PWD}:/cwd" \
   -w /cwd \
   doraeric/p4c \
   p4c-bm2-ss

P4FLAGS=--arch v1model -DTARGET_BMV2
BUILD_DIR=build

.PHONY: all ccsa env

all:
	mkdir -p $(BUILD_DIR)
	$(P4C) $(P4FLAGS) \
		-o build/bmv2.json --p4runtime-files build/p4info.txt src/basic.p4

ccsa:
	$(eval BUILD_DIR := build-ccsa)
	mkdir -p $(BUILD_DIR)
	$(P4C) $(P4FLAGS) -DCCSA \
		-o $(BUILD_DIR)/bmv2.json --p4runtime-files $(BUILD_DIR)/p4info.txt src/basic.p4

env:
	@# eval `make env`
	$(eval P4BIN := $(shell readlink -f build/bmv2.json))
	$(eval P4INFO := $(shell readlink -f build/p4info.txt))
	@echo export P4INFO=\"${P4INFO}\" P4BIN=\"${P4BIN}\"
