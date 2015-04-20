'''
    File: Router.py
    Course: COSC364
    Date: 20/04/2015
    Authors: Andrew Dallow (56999204), Dillon George ([INSERT ID HERE])
    
    Summary: Program that implements a routing deamon based on the 
             RIP version 2 protocol from RFC2453.
    
    Usage: python3 Router.py <router_config_file>
    
    Configuration File:
    
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
                 
    Description:
        
        This program implements a basic RIPv2 routing protocol from RFC2453
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
                
'''
import configparser
import select
import socket
import sys
import time
import threading
import struct
import datetime
from random import randint, randrange

HOST = '127.0.0.1'  # localhost
BASE_TIMER = 5
MAX_METRIC = 16
ROUTE_TIMEOUT = BASE_TIMER * 6
DELETE_TIMEOUT = BASE_TIMER * 4

AF_INET = 2

# ===========================================================================
# TRANSITIONS


class Transistion():

    '''Class Representing a transition between states.'''

    def __init__(self, to_state):
        self.to_state = to_state

    def execute(self):
        '''Run the transition functions'''
        pass


# ===========================================================================
# STATES


class State():

    '''Class Representing a generic state'''

    def __init__(self, fsm):
        self.fsm = fsm

    def enter(self):
        '''Execute functions for entering a state'''
        pass

    def execute(self):
        '''Execute functions while in state'''
        pass

    def exit(self):
        '''Execute functions for leaving a state'''
        pass


class StartUp(State):

    '''Class Representing the Start up state which reads the configuration file
    '''

    def __init__(self, fsm):
        super(StartUp, self).__init__(fsm)

    def execute(self):
        '''Execute the configuration functions'''

        print_message("Loading Configuration File: '"
                      + self.fsm.router.config_file + "'")

        config = configparser.ConfigParser()
        config.read(self.fsm.router.config_file)

        self.get_router_id(config)
        self.setup_inputs(config)
        self.get_outputs(config)

        self.setup_routing_table()
        self.fsm.router.print_routing_table()

        self.fsm.to_transition("toWaiting")

    def exit(self):
        '''Print complete message'''

        print_message("Router Setup Complete.")

    def get_router_id(self, config):
        '''Read the router id number from the configuration file'''

        if 1 <= int(config['Settings']['router-id']) <= 64000:
            self.fsm.router.router_settings['id'] = \
                int(config['Settings']['router-id'])
        else:
            raise Exception('Invalid Router ID Number')

    def get_outputs(self, config):
        '''Return a dictionary of outputs containing port, cost and destination
        router id from the Configuration file'''

        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]

        self.fsm.router.router_settings['outputs'] = {}
        existing_ports = []

        for output in outputs:
            is_valid_port = 1024 <= int(output[0]) <= 64000 and not \
                int(output[0]) in existing_ports

            is_valid_cost = 1 <= int(output[1]) < 16
            is_valid_id = 1 <= int(output[2]) <= 64000
            if is_valid_port and is_valid_cost and is_valid_id:
                existing_ports.append(int(output[0]))
                self.fsm.router.router_settings['outputs'][int(output[2])] = \
                    {'metric': int(output[1]),
                     'port': int(output[0])}
            else:
                raise Exception('Invalid Outputs')

    def setup_inputs(self, config):
        '''Create input sockets from the inputs specified in the config file'''

        # get inputs from configuration file
        ports = config['Settings']['input-ports'].split(', ')

        inputs = []
        for port in ports:
            if 1024 <= int(port) <= 64000 and not int(port) in inputs:
                inputs.append(int(port))
            else:
                raise Exception('Invalid Port Number')

        self.fsm.router.router_settings['inputs'] = {}
        # create socket for each input port
        for port in inputs:
            try:
                self.fsm.router.router_settings['inputs'][port] = \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                print_message('Socket ' + str(port) + ' Created.')
            except socket.error as msg:
                print('Failed to create socket. Message: ' + str(msg))
                sys.exit()

            # bind port to socket
            try:
                self.fsm.router.router_settings['inputs'][port].bind(
                    (HOST, port))

                print_message('Socket ' + str(port) + ' Bind Complete.')
            except socket.error as msg:
                print('Failed to create socket. Message ' + str(msg))
                sys.exit()

    def setup_routing_table(self):
        '''Setup routing table with the outputs specified in the config file'''

        self.fsm.router.routing_table[self.fsm.router.router_settings['id']] = \
            RIPRouteEntry(address=self.fsm.router.router_settings['id'],
                          nexthop=0,
                          metric=0,
                          imported=True)


class Waiting(State):

    '''
        Class representing the waiting state of the FSM where the router waits
        for messages to be received on its input sockets. When a message is
        received the state changes to the ReadMeassage state.
    '''

    def __init__(self, fsm):
        super(Waiting, self).__init__(fsm)

    def enter(self):
        '''Display State entry message'''
        print_message("Entering idle state...")

    def execute(self):
        '''Waits for input sockets to be readable and then changes the state
        to process the received message.'''

        readable = select.select(
            self.fsm.router.router_settings['inputs'].values(), [], [])

        if readable[0]:
            self.fsm.router.readable_ports = readable[0]
            self.fsm.to_transition("toReadMessage")

    def exit(self):
        '''Display State exit message'''
        print_message("Message Received")


class ReadMessage(State):

    '''Class representing the state for reading messages received on the input
    sockets'''

    def __init__(self, fsm):
        super(ReadMessage, self).__init__(fsm)

    def enter(self):
        print_message("Reading Messages...")

    def execute(self):

        for port in self.fsm.router.readable_ports:

            packet = RIPPacket(port.recvfrom(1024)[0])

            self.fsm.router.update_routing_table(packet)

        if self.fsm.router.route_change:
            self.fsm.router.trigger_update()

        self.fsm.router.print_routing_table()
        self.fsm.to_transition("toWaiting")

    def exit(self):
        print_message("Messages Read.")

# ===========================================================================
# FINITE STATE MACHINE


class RouterFSM():

    '''Class representing the Router finite state machine'''

    def __init__(self, rip_router):
        self.router = rip_router
        self.states = {}
        self.transitions = {}
        self.cur_state = None
        self.trans = None

    def add_transistion(self, trans_name, transition):
        '''Add a new transition to the FSM'''
        self.transitions[trans_name] = transition

    def add_state(self, state_name, state):
        '''Add a new state to the FSM'''
        self.states[state_name] = state

    def set_state(self, state_name):
        '''Set the current state of the FSM'''
        self.cur_state = self.states[state_name]

    def to_transition(self, to_trans):
        '''Set the current transition of the FSM'''
        self.trans = self.transitions[to_trans]

    def execute(self):
        '''Run the FSM'''

        if self.trans:
            self.cur_state.exit()
            self.trans.execute()
            self.set_state(self.trans.to_state)
            self.cur_state.enter()
            self.trans = None
        self.cur_state.execute()


# ===========================================================================
# IMPLEMENTATION

class RIPPacket:

    '''Class representing a RIP packet containing a header and body as defined
    in RFC2453 RIPv2 section 4.'''

    def __init__(self, data=None, header=None, rtes=None):

        if data:
            self._init_from_network(data)

        elif header and rtes:
            self._init_from_host(header, rtes)

        else:
            raise ValueError

    def __repr__(self):
        return "RIPPacket: Command {}, Ver. {}, number of RTEs {}.". \
            format(self.header.cmd, self.header.ver, len(self.rtes))

    def _init_from_network(self, data):
        '''Init for RIPPacket if data is from the network'''

        # Packet Validation
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise FormatException

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE

        if malformed_rtes:
            raise FormatException

        # Convert bytes in packet to header and RTE data
        num_rtes = int((datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE)

        self.header = RIPHeader(data[0:RIPHeader.SIZE])

        self.rtes = []

        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE

        # Loop over data packet to obtain each RTE
        for i in range(num_rtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end],
                                           src_id=self.header.src))

            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    def _init_from_host(self, header, rtes):
        '''Init for imported data'''

        if header.ver != 2:
            raise ValueError("Only Version 2 is supported.")
        self.header = header
        self.rtes = rtes

    def serialize(self):
        '''Return the byte sting representing this packet for network
        transmission'''

        packed = self.header.serialize()

        for rte in self.rtes:
            packed += rte.serialize()

        return packed


class RIPHeader:

    '''Class representing the header of a RIP packet'''

    FORMAT = "!BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_RESPONSE = 2
    VERSION = 2

    def __init__(self, rawdata=None, router_id=None):

        self.packed = None

        if rawdata:
            self._init_from_network(rawdata)
        elif router_id:
            self._init_from_host(router_id)
        else:
            raise ValueError

    def __repr__(self):
        return "RIP Header (cmd = {}, ver = {}, src = {})".format(self.cmd,
                                                                  self.ver,
                                                                  self.src)

    def _init_from_network(self, rawdata):
        '''init for data from network'''
        header = struct.unpack(self.FORMAT, rawdata)

        self.cmd = header[0]
        self.ver = header[1]
        self.src = header[2]

    def _init_from_host(self, router_id):
        '''Init for data from host'''
        self.cmd = self.TYPE_RESPONSE
        self.ver = self.VERSION
        self.src = router_id

    def serialize(self):
        '''Return the byte sting representing this header for network
        transmission'''
        return struct.pack(self.FORMAT, self.cmd, self.ver, self.src)


class RIPRouteEntry:

    '''Class representing a single RIP route entry (RTE)'''

    FORMAT = "!HHIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    def __init__(self, rawdata=None, src_id=None, address=None,
                 nexthop=None, metric=None, imported=False):

        self.changed = False
        self.imported = imported
        self.init_timeout()

        if rawdata and src_id != None:
            self._init_from_network(rawdata, src_id)
        elif address and nexthop != None and metric != None:
            self._init_from_host(address, nexthop, metric)
        else:
            raise ValueError

    def __repr__(self):
        template = "|{:^11}|{:^10}|{:^11}|{:^15}|{:^10}|"
        if self.timeout == None:

            return template.format(self.addr, self.metric, self.nexthop,
                                   self.changed, self.timeout)

        else:
            return template.format(self.addr, self.metric, self.nexthop,
                                   self.changed,
                                   self.timeout.strftime("%H:%M:%S"))

    def _init_from_host(self, address, nexthop, metric):
        '''Init for data from host'''
        self.afi = AF_INET
        self.tag = 0  # not used
        self.addr = address
        self.nexthop = nexthop
        self.metric = metric

    def _init_from_network(self, rawdata, src_id):
        '''Init for data received from network'''
        rte = struct.unpack(self.FORMAT, rawdata)

        self.afi = rte[0]
        self.tag = rte[1]
        self.addr = rte[2]
        self.set_nexthop(rte[3])
        self.metric = rte[4]

        if self.nexthop == 0:
            self.nexthop = src_id

        # Validation
        if not self.MIN_METRIC <= self.metric <= self.MAX_METRIC:
            raise FormatException

    def init_timeout(self):
        '''Initialize the timeout property'''

        if self.imported:
            self.timeout = None
        else:
            self.timeout = datetime.datetime.now()

        self.garbage = False
        self.marked_for_delection = False

    def __eq__(self, other):

        if self.afi == other.afi and \
           self.addr == other.addr and \
           self.tag == other.tag and \
           self.nexthop == other.nexthop and \
           self.metric == other.metric:
            return True
        else:
            return False

    def set_nexthop(self, nexthop):
        '''Set the nexthop property'''
        self.nexthop = nexthop

    def serialize(self):
        '''Pack entries into typical RIPv2 packet format for sending over the
        network. '''
        return struct.pack(self.FORMAT, self.afi, self.tag, self.addr,
                           self.nexthop, self.metric)


class FormatException(Exception):

    '''Class representing the Format Exception'''

    def __init__(self, message=""):
        self.message = message


class Router:

    '''Class representing a single router'''

    def __init__(self, config_file):

        self.fsm = RouterFSM(self)
        self.config_file = config_file

        # Dictionary of router settings, including router-id, inputs and
        # outputs
        self.router_settings = {}
        self.readable_ports = []

        # Dictionary of routing table
        self.routing_table = {}

        self.route_change = False

        # STATES
        self.fsm.add_state("StartUp", StartUp(self.fsm))
        self.fsm.add_state("Waiting", Waiting(self.fsm))
        self.fsm.add_state("ReadMessage", ReadMessage(self.fsm))

        # TRANSITIONS
        self.fsm.add_transistion("toWaiting", Transistion("Waiting"))
        self.fsm.add_transistion("toReadMessage", Transistion("ReadMessage"))

        self.fsm.set_state("StartUp")

    def execute(self):
        '''Run the router's finite state machine'''
        self.fsm.execute()

    def update_routing_table(self, packet):
        '''Update Routing table if new route info exist'''

        for rte in packet.rtes:
            # ignore RTEs of self
            if rte.addr != self.fsm.router.router_settings['id']:

                bestroute = self.routing_table.get(rte.addr)

                # set nexthop to source router and calculate metric
                rte.set_nexthop(packet.header.src)
                rte.metric = min(rte.metric +
                                 self.router_settings['outputs'][
                                     packet.header.src]['metric'],
                                 RIPRouteEntry.MAX_METRIC)

                # Route  dosn't yet exist
                if not bestroute:
                    # ignore RTEs with a metric of MAX_METRIC
                    if rte.metric == RIPRouteEntry.MAX_METRIC:
                        return

                    # Add new RTE to routing table
                    rte.changed = True
                    self.route_change = True
                    self.routing_table[rte.addr] = rte
                    print_message("RTE added for Router: " + str(rte.addr))
                    return
                else:
                    # Route already exists
                    if rte.nexthop == bestroute.nexthop:
                        if bestroute.metric != rte.metric:
                            if bestroute.metric != RIPRouteEntry.MAX_METRIC \
                               and rte.metric >= RIPRouteEntry.MAX_METRIC:
                                # mark for garbage collection
                                bestroute.metric = RIPRouteEntry.MAX_METRIC
                                bestroute.garbage = True
                                bestroute.changed = True
                                self.route_change = True
                            else:
                                self.update_route(bestroute, rte)
                        # Route still exists with same values
                        elif not bestroute.garbage:
                            bestroute.init_timeout()
                    # Lower metric on existing route
                    elif rte.metric < bestroute.metric:
                        self.update_route(bestroute, rte)

    def update_route(self, bestroute, rte):
        '''Update an existing route entry with new route info'''

        bestroute.init_timeout()
        bestroute.garbage = False
        bestroute.changed = True
        bestroute.metric = rte.metric
        bestroute.nexthop = rte.nexthop
        self.route_change = True
        print_message("RTE for Router: " + str(rte.addr) +
                      " updated with metric=" + str(rte.metric) +
                      ", nexthop=" + str(rte.nexthop) + ".")

    def print_routing_table(self):
        '''Print the routing table to the terminal'''
        line = "+-----------+----------+-----------+---------------+----------+"
        print(line)
        print(
            "|                      Routing Table                          |")
        print(line)
        print(
            "|Router ID  |  Metric  |  NextHop  |  ChangedFlag  |  Timeout |")
        print(
            "+-----------+----------+-----------+---------------+----------+")

        for entry in self.routing_table:
            print(self.routing_table[entry])
            print(line)

    def trigger_update(self):
        '''Send Routing update for only the routes which have changed'''
        changed_rtes = []
        print_message("Sending Trigger update.")
        for rte in self.routing_table.values():
            if rte.changed:
                changed_rtes.append(rte)
                rte.changed = False

        self.route_change = False
        # send update with random delay between 1 and 5 seconds
        delay = randint(1, 5)
        threading.Timer(delay, self.update, [changed_rtes])

    def update(self, entries):
        '''Send a message to all output ports'''
        if self.router_settings != {}:

            sock = list(self.router_settings['inputs'].values())[1]
            local_header = RIPHeader(router_id=self.router_settings['id'])

            packet = RIPPacket(header=local_header, rtes=entries)

            for output in self.router_settings['outputs']:
                sock.sendto(packet.serialize(),
                            (HOST,
                             self.router_settings['outputs'][output]["port"]))

                print_message("Message Sent To Router: " + str(output))

    def check_timeout(self):
        '''Check the current timeout value for each RTE in the routing table.
        If the time difference with now is greater than ROUTE_TIMEOUT, then
        set the metric to 16 and start the garbage collection timer.'''

        print_message("Checking timeout...")
        if self.routing_table != {}:

            for rte in self.routing_table.values():
                if rte.timeout != None and \
                   (datetime.datetime.now() - rte.timeout).total_seconds() \
                   >= ROUTE_TIMEOUT:
                    rte.garbage = True
                    rte.changed = True
                    self.route_change = True
                    rte.metric = RIPRouteEntry.MAX_METRIC
                    rte.timeout = datetime.datetime.now()
                    self.print_routing_table()
                    print_message("Router: " + str(rte.addr) + " timed out.")

    def garbage_timer(self):
        '''Check the status of the garbage property of each RTE. If true, and
        the timeout value difference with now is greater than DELETE_TIMEOUT,
        mark it for deletion'''

        print_message("Checking garbage timeout...")
        if self.routing_table != {}:
            for rte in self.routing_table.values():
                if rte.garbage:
                    if (datetime.datetime.now() - rte.timeout).total_seconds() \
                            >= DELETE_TIMEOUT:
                        rte.marked_for_delection = True

    def garbage_collection(self):
        '''Check the routing table for RTE's that are marked for deletion and
        remove them.'''

        print_message("Collecting Garbage...")
        if self.routing_table != {}:
            delete_routes = []
            for rte in self.routing_table.values():
                if rte.marked_for_delection:
                    delete_routes.append(rte.addr)
                    print_message("Router: " + str(rte.addr) + " has been " +
                                  "removed from the routing table.")

            for entry in delete_routes:
                del self.routing_table[entry]
                self.print_routing_table()

    def timer(self, function, param=None):
        '''Start a periodic timer which calls a specified function'''

        if param != None:
            function(list(param.values()))
            period = BASE_TIMER * randrange(8, 12, 1) / 10
        else:
            period = BASE_TIMER
            function()

        threading.Timer(period, self.timer, [function, param]).start()

    def start_timers(self):
        '''Start the timers on separate threads'''
        self.timer(self.update, param=self.routing_table)
        self.timer(self.check_timeout)
        self.timer(self.garbage_timer)
        self.timer(self.garbage_collection)

    def main_loop(self):
        '''Start the main loop for the program.'''

        while True:
            self.execute()

# RUN THE PROGRAM


def print_message(message):
    '''Print the given message with the current time before it'''
    print("[" + time.strftime("%H:%M:%S") + "]: " + message)


def main():
    '''Main function to run the program.'''

    if __name__ == "__main__":
        router = Router(str(sys.argv[-1]))
        router.start_timers()
        router.main_loop()

main()
