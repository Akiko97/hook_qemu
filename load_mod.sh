#!/bin/sh
/sbin/rmmod hook_qemu_mod
cpstings_address=`grep copy_strings.isra /proc/kallsyms | awk {'print $1'}`
/sbin/insmod ./hook_qemu_mod.ko hook_address=0x$cpstings_address
