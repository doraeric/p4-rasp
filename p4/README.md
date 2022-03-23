# P4 Program

The code is extended from [onos basic pipeline](https://github.com/opennetworkinglab/onos/tree/2.7.0/pipelines/basic/src/main/resources) with [p4 tutorials](https://github.com/p4lang/tutorials/blob/master/exercises/basic/solution/basic.p4).

It's generated with the commands:

```sh
rsync -az --info=progress2 --mkpath ./third_party/onos/pipelines/basic/src/main/resources/include/ ./p4/src/include/
rsync -az --info=progress2 --mkpath ./third_party/onos/pipelines/basic/src/main/resources/basic.p4 ./p4/src/
```
