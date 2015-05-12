#!/bin/sh

pids=$(<pid_list.txt)
echo $pids

for pid in $pids
do
   kill $pid
done
