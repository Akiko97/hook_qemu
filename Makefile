BUILD ?= /lib/modules/`uname -r`/build

hook_qemu_mod-objs := hook_qemu.o
obj-m := hook_qemu_mod.o

all:
	$(MAKE) -C $(BUILD) M=$(PWD) modules;

clean:
	$(MAKE) -C $(BUILD) SUBDIRS=$(PWD) clean;
	rm -f *.ko
