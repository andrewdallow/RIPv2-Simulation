# RIPv2 Routing Simulation - Python 3

Authors: Andrew Dallow and Dillion George 

Summary: Program that implements a routing deamon based on the 
     RIP version 2 protocol from RFC2453.

Usage: python3 Router.py <router_config_file>

### Configuration File:

The user supplies a router configuration file of the format:

     [Settings]
     router-id = <router_number>
     input-ports = <input> [, <input>, ...]
     outputs = <output>-<metric>-<destination_router>
                         [, <output>-<metric>-<destination_router>, ...]

where,
 router_number: ID of router between 1 - 64000.
 input: port number between 1024 - 64000.
 output: port number between 1024 - 6400, 
         not equal to any inputs.
 metric: metric of output between 1 - 16.
 destination_router: ID of destination router.

### Description:

This program implements a basic RIPv2 routing protocol from [RFC2453](https://tools.ietf.org/html/rfc2453)
for routing computations in computer networks. It takes a configuration 
file as shown above and sets up a router with a new socket for each 
input-port.

The RIPv2 protocol uses a routing table to keep track of all reachable
routers on the network along with their metric/cost and the direct
next hop router ID along the route to that destination router. However, 
it can only send messages to the direct neighbours specified in outputs. 
The protocol uses the Bellman-Ford distance vector algorithm to compute
the lowest cost route to each router in the network. If the metric is
16 or greater, the router is considered unreachable.

The routing table initially starts with a single route entry (RTE) for
itself with a metric of zero. The routing table is periodically 
transmitted too each of its direct output ports via an unsolicited 
response message as defined in RFC2453 section 3.9.2 and 4. This is 
performed on a separate thread so it does not interfere with other 
operations

The receives messages from other routers by using the python select() 
function which blocks until a message is ready to be read. Once a 
message is received the header and contents are validated. 
If the message is valid each RTE is processed according to RFC2453 
section 3.9.2. 
        
      If a new router is found the RTE is added 
      to the routing table, adding the cost to the metric for the output 
      the message was received on. 

      If the RTE already exists, but the metric is smaller, the metric
      is updated to the lower metric.

      If the lower metric is from a different next hop router, change the
      next hop. 

      If nothing has changed, restart the timeout timer. 

      If RTE metric >= max metric of 16, mark the entry for
      garbage collection and update the metric in the table. 

  If any change has occurred in the routing table as a result of a 
  received message, a triggered update (RFC2453 section 3.10.1) is sent 
  to all outputs with the updated entries. Triggered updates are sent with
  a random delay between 1 - 5 seconds to prevent synchronized updates.

  Request messages are not implemented in this program.

  Timers (all timers are on separate threads) (RFC2453 section 3.8):

      Update timer - Periodic unsolicited response message sent to all
          outputs. The period is adjusted each time to a random value 
          between 0.8 * BASE_TIMER and 1.2 * BASE_TIMER to prevent 
          synchronized updates. 

      Timeout - used to check the routing table for RTEs which have
          have not been updated within the ROUTE_TIMEOUT interval. If
          a router has not been heard from within this time, then set the
          metric to the max metric of 16 and start the garbage collection
          timer.

      Garbage timer - used to check the routing table for RTEs set 
          for garbage collection. If the timeout >= DELETE_TIMEOUT, 
          mark the RTE for deletion.

      Garbage Collection - used to check the routing table for RTEs 
          marked for deletion, and removes those entries from the table. 
 
 ## License ##
      Copyright 2016 Andrew Dallow

      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
      You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
      See the License for the specific language governing permissions and
      limitations under the License.
 
