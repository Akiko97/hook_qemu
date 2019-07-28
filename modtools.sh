#!/bin/bash
if [[ $USER == "root" ]]
then
	if [ -n "$1" ]
	then
		case "$1" in
			load)
				cpstings_address=`grep copy_strings.isra /proc/kallsyms | awk {'print $1'}`
				/sbin/insmod ./hook_qemu_mod.ko hook_address=0x$cpstings_address
				if [[ $? == 0 ]]
				then
					echo "dmesg: "
					echo "`dmesg | tail -n2`"
				fi ;;
			remove)
				/sbin/rmmod hook_qemu_mod
				if [[ $? == 0 ]]
				then
					echo "dmesg: "
					echo "`dmesg | tail -n2`"
				fi ;;
			*)
				echo "Usage: sudo $0 [load | remove]" ;;
		esac
	else
		echo "Usage: sudo $0 [load | remove]"
	fi
else
	echo "this script must run as root user"
fi
