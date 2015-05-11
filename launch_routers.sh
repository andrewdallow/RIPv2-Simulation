#!/bin/sh

ROUTERS="1 2 3 4 5 6 7"

for rout_num in $ROUTERS
do
  gnome-terminal -x python3 Router.py "router_$rout_num.txt" & pids="${pids-} $!"
done
echo $pids

echo $pids > pid_list.txt
