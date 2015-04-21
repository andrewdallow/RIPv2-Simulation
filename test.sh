#!/bin/bash

# Tests implementation of Split-horizon routing with poison reverse
# Routers 1, 2 and three are connected thusly
#                (1)------(2)------(3)
# If not Split-horizon with poison reverse(SHPR) is not implemented
# and link between 2-3 goes down, a loop between 1 and 2 will form
# as router 1 advertises a route to (3) and so router (2) will update
# its routing table with that entry once the broken link is detected.
# Because of this the router 3 is not removed from the routing table until
# the metric reaches infinity(16 in this case).

# With SHPR implemented this should take significantly less time and converge
# Faster
ROUTERS="1 2 3"

for rout_num in $ROUTERS
do
	python3 Router.py "router_$rout_num.txt" & pids="${pids-} $!"
	sleep 2
done
echo $pids
echo $pids > pid_list.txt

ACTIVE_ROUTERS=($pids)

sleep 30 # wait for routing tables to update

# kill router 3
kill ${ACTIVE_ROUTERS[2]}
echo "KILLED ROUTER 3"
echo ${ACTIVE_ROUTERS[0]} ${ACTIVE_ROUTERS[1]} > pid_list.txt
