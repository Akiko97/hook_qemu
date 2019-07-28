# hook_qemu
hook qemu-system-x86_64 and add vtcm support

## Usage

compile:

* in `./`:

  ```shell
  make
  ```

* in `cube_module/src/show_vtcm` and `cube_module/src/vtcm_memdb`:

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
chmod 777 ./run_qemu.sh
./run_qemu.sh
```

