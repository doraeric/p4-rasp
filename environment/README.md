# Environment Setup

This directory contains files and docs to setup data plane and control plane environments

## p4runtime-shell

```sh
# optional: use venv
python -m venv venv && . ./venv/bin/activate && python -m pip install -U pip

pip install git+https://github.com/p4lang/p4runtime-shell
```

## Docker image

The image is for mininet and p4 switch.

Copy the `environment` folder to other place and add files if you want.
For the photo experiment, there should be a `landscape-photo` folder containing 10 photos.

In the folder containing `Dockerfile.p4mn-dev`, build docker image:

```sh
docker build -t doraeric/p4mn:latest-dev -f Dockerfile.p4mn-dev .
```


Add mininet command alias to `~/.bashrc`

```sh
alias mn='docker run --privileged --rm -it \
  --net=host \
  -v "`pwd`":/cwd \
  -w /cwd \
  --name p4mn_01 \
  -e TERM \
  doraeric/p4mn:latest-dev'
```
