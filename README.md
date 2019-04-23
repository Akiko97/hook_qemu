# hook_qemu
hook qemu-system-x86_64 and add vtcm support

## Usage

compile:

```shell
make
```

load:

```shell
sudo chmod 777 ./modtools.sh
sudo ./modtools.sh load
```

remove:

```shell
sudo chmod 777 ./modtools.sh
sudo ./modtools.sh remove
```

***NEED CUBE-TCM SUPPORT!***

build cube-tcm environment => [here](<https://github.com/Akiko97/auto-vtcm>)
## Run QEMU
```shell
qemu-system-x86_64 -m 1024 -smp 4 -hda ./ubuntu.img
```
