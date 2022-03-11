.PHONY: copy

copy:
	rsync -az --info=progress2 --mkpath ./third_party/onos/pipelines/basic/src/main/resources/include/ ./p4/src/include/
	rsync -az --info=progress2 --mkpath ./third_party/onos/pipelines/basic/src/main/resources/basic.p4 ./p4/src/
