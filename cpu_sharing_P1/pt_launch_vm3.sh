#!/bin/bash

# offline SOS CPUs except BSP before launch UOS
for i in `ls -d /sys/devices/system/cpu/cpu[1-99]`; do
        online=`cat $i/online`
        idx=`echo $i | tr -cd "[1-99]"`
        echo cpu$idx online=$online
        if [ "$online" = "1" ]; then
                echo 0 > $i/online
                echo $idx > /sys/class/vhm/acrn_vhm/offline_cpu
        fi
done

/usr/bin/acrn-dm -A -m 1024M --debugexit -E $1 -s 0:0,hostbridge --lapic_pt -s 1:0,lpc -l com2,stdio   \
	-U 38158821-5208-4005-b72a-8a609e4190d0  acrn_vxworks 

