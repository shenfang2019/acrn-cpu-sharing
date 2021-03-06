#!/bin/bash

# offline SOS CPUs except BSP before launch UOS
for i in `ls -d /sys/devices/system/cpu/cpu[2-99]`; do
        online=`cat $i/online`
        idx=`echo $i | tr -cd "[2-99]"`
        echo cpu$idx online=$online
        if [ "$online" = "1" ]; then
                echo 0 > $i/online
                #echo $idx > /sys/devices/virtual/misc/acrn_hsm/remove_cpu
                echo $idx > /sys/class/vhm/acrn_vhm/offline_cpu
        fi
done

/usr/bin/acrn-dm -A -m 1024M --debugexit -E $1 -s 0:0,hostbridge -s 1:0,lpc -l com2,stdio --lapic_pt --rtvm --virtio_poll 1000000 -U 495ae2e5-2603-4d64-af76-d4bc5a8ec0e5 acrn-rtvm

