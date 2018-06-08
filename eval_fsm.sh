#!/bin/sh

sudo insmod fsm.ko

start_time=`date +%s`
while :
do
	end_time=`date +%s`
	diff_time=$((end_time - start_time))
	echo "time[s] : $diff_time" >> state_nomal.txt
	sudo dmesg --clear
	uname
	dmesg | grep forensic >> state_nomal.txt
	if [ $diff_time -gt 60 ]; then
		break
	fi
	sleep 1.0
done
