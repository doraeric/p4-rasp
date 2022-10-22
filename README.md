# P4 DDoS Defense

## Prerequisites

- linux environment for the scripts
- [docker](https://www.docker.com/) for compiling P4 and data plane
- [p4runtime-shell](https://github.com/p4lang/p4runtime-shell) for control plane
- nc: optional for logging, `apt install netcat-openbsd`

See environment/README.md for more.

## Compile P4

```sh
cd p4
make
```

## Start data plane

```sh
cd experiments/02-slow-ddos
mn --custom mn_custom.py --topo ccsa-2s
```

## Start control plane

Show logging message in the same terminal:

```sh
cd experiments/02-slow-ddos
./10_p4_control.py --topo topos/ccsa-2s.json each -s 2 -l -a
```

To show log in a separate terminal, use the following commands:

```
# window 1
nc -klvp 3000

# window 2
./10_p4_control.py --log tcp:localhost:3000 --topo topos/ccsa-2s.json each -s 2 -l -a
```

## Start attack simulation

Try 20-xxx scripts.
