'''
   Program that implements a routing deamon based on the RIP version 2 protocol.
   Can be run by: python3 RouterFSM.py <router_config_file>

   Authors:
       Andrew Dallow
       Dillon George
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
<<<<<<< HEAD
    def __init__(self, FSM):
        self.FSM = FSM
=======

    '''Class Representing a generic state'''

    def __init__(self, fsm):
        self.fsm = fsm
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

    def enter(self):
        '''Execute functions for entering a state'''
        pass

    def execute(self):
        '''Execute functions while in state'''
        pass

    def exit(self):
        '''Execute functions for leaving a state'''
        pass

<<<<<<< HEAD
    def printMessage(self, message):
        print("[" + time.strftime("%H:%M:%S") + "]: " + message)

class StartUp(State):
    def __init__(self, FSM):
        super().__init__(FSM)
        #super(StartUp, self).__init__(FSM)

    def enter(self):
        pass        

    def execute(self):
        self.printMessage("Loading Configuration File: '" 
                          + self.FSM.router.config_file + "'")

        config = configparser.ConfigParser()
        config.read(self.FSM.router.config_file)        
=======

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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

        self.get_router_id(config)
        self.setup_inputs(config)
        self.get_outputs(config)

<<<<<<< HEAD
        self.setup_inputs()

        self.FSM.toTransition("toWaiting") 

    def exit(self):
        self.printMessage("Router Setup Complete.")
=======
        self.setup_routing_table()
        self.fsm.router.print_routing_table()

        self.fsm.to_transition("toWaiting")

    def exit(self):
        '''Print complete message'''

        print_message("Router Setup Complete.")
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

    def get_router_id(self, config):
        '''Read the router id number from the configuration file'''

        if 1 <= int(config['Settings']['router-id']) <= 64000:
            self.fsm.router.router_settings['id'] = \
                int(config['Settings']['router-id'])
        else:
<<<<<<< HEAD
            raise Exception('Invalid Router ID Number')  

    def get_input_ports(self, config):
        '''Read and parse a list of input port numbers from the 
        configuration file'''        

        ports = config['Settings']['input-ports'].split(', ')        

        for port in ports:
            if 1024 <= int(port) <= 64000:
                self.FSM.router.input_ports.append(int(port))
            else:
                raise Exception('Invalid Port Number') 

    def print_router_info(self):
        '''Print information about the router'''
        print('Router ID: {}'.format(self.router_id))
        print('Input Ports: {}'.format(
            ', '.join(str(x) for x in self.input_ports)))
        print('Outputs: ')
        for output in self.outputs:
            print (output)
            for values in self.outputs[output]:
                print (values, ':', self.outputs[output][values])


=======
            raise Exception('Invalid Router ID Number')
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

    def get_outputs(self, config):
        '''Return a dictionary of outputs containing port, cost and destination
        router id from the Configuration file'''

        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]

<<<<<<< HEAD
=======
        self.fsm.router.router_settings['outputs'] = {}
        existing_ports = []

>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
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

<<<<<<< HEAD

    def setup_inputs(self):

        #create socket for each input port
        for port in self.FSM.router.input_ports:
=======
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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
            try:
                self.fsm.router.router_settings['inputs'][port] = \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                print_message('Socket ' + str(port) + ' Created.')
            except socket.error as msg:
                print('Failed to create socket. Message: ' + str(msg))
                sys.exit()

<<<<<<< HEAD
            #bind port to socket
=======
            # bind port to socket
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
            try:
                self.fsm.router.router_settings['inputs'][port].bind(
                    (HOST, port))

                print_message('Socket ' + str(port) + ' Bind Complete.')
            except socket.error as msg:
                print('Failed to create socket. Message ' + str(msg))
                sys.exit()

    def setup_routing_table(self):
        '''Setup routing table with the outputs specified in the config file'''

        for output in self.fsm.router. router_settings['outputs']:
            self.fsm.router.routing_table[output] = \
                RIPRouteEntry(address=output,
                              nexthop=output,
                              metric=self.fsm.router.
                              router_settings['outputs'][output]["metric"],
                              imported=True)


class Waiting(State):
<<<<<<< HEAD
    def __init__(self, FSM):
        super().__init__(FSM)
#        super(Waiting, self).__init__(FSM)
        self.printMessage("Entering idle state...")

    def execute(self):   

        readable, writable, exceptional = select.select(
                                        self.FSM.router.connections.values(), 
                                        [], [])        

        if readable:
            self.FSM.readable = readable
            self.FSM.toTransition("toReadMessage")

    def exit(self):
        self.printMessage("Message Received")


class ReadMessage(State):
    def __init__(self, FSM):
        super(ReadMessage, self).__init__(FSM)

    def enter(self):
        self.printMessage("Reading Message...")

    def execute(self):
        for port in self.FSM.readable:
            received = port.recvfrom(1024)
            data = received[0].decode('utf-8')
            addr = received[1]

            #Process received data
            if data:  
                self.printMessage('Message[' + addr[0] + ':' 
                      + str(port.getsockname()[1]) + '] - ' + data.strip())

        self.FSM.toTransition("toWaiting")

    def exit(self):
        self.printMessage("Message Read.")
=======

    '''
        Class representing the waiting state of the FSM where the router waits
        for messages to be received on its input sockets. When a message is
        received the state changes to the ReadMeassage state.
    '''
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

    def __init__(self, fsm):
        super(Waiting, self).__init__(fsm)

<<<<<<< HEAD
class ValidateMessageHeader(State):
    def __init__(self, FSM):
        super(ValidateMessageHeader, self).__init__(FSM)

    def enter(self):
        pass

    def execute(self):

        isHeaderValid = self.validateHeader(message)

        if isHeaderValid:
            self.FSM.toTransition("toProcessAllRTEs") 
        else:
            self.FSM.toTransition("toWaiting") 

    def exit(self):
        pass

    def validateHeader(self, message):
        '''Check message header'''
        return False
=======
    def enter(self):
        '''Display State entry message'''
        print_message("Entering idle state...")

    def execute(self):
        '''Waits for input sockets to be readable and then changes the state
        to process the received message.'''
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

        readable = select.select(
            self.fsm.router.router_settings['inputs'].values(), [], [])

        if readable[0]:
            self.fsm.router.readable_ports = readable[0]
            self.fsm.to_transition("toReadMessage")

<<<<<<< HEAD
class ProcessAllRTEs(State):
    def __init__(self, FSM):
        super(ProcessAllRTEs, self).__init__(FSM)

    def enter(self):
        pass

    def execute(self):
        pass

=======
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
    def exit(self):
        '''Display State exit message'''
        print_message("Message Received")


<<<<<<< HEAD
class TriggerUpdate(State):
    def __init__(self, FSM):
        super(TriggerUpdate, self).__init__(FSM)

    def enter(self):
        pass

    def execute(self):
        pass

    def exit(self):
        pass
=======
class ReadMessage(State):

    '''Class representing the state for reading messages received on the input
    sockets'''
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

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

<<<<<<< HEAD
    def addTransistion(self, trandName, transition):
        self.transitions [trandName] = transition

    def addState(self, stateName, state):
        self.states[stateName] = state

    def setState(self, stateName):
        self.curState = self.states[stateName]

    def toTransition(self, toTrans):
        self.trans = self.transitions[toTrans]

    def transition(self):
        self.curState.exit()
        self.trans.execite()
=======
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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

    def execute(self):
        '''Run the FSM'''

        if self.trans:
<<<<<<< HEAD
            # Wrap this all in transiton method
            self.curState.exit()
=======
            self.cur_state.exit()
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
            self.trans.execute()
            self.set_state(self.trans.to_state)
            self.cur_state.enter()
            self.trans = None
<<<<<<< HEAD
        self.curState.execute()

=======
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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

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

        rte_self = RIPRouteEntry(address=header.src,
                                 nexthop=0,
                                 metric=0,
                                 imported=True)

        if header.ver != 2:
            raise ValueError("Only Version 2 is supported.")
        self.header = header
        self.rtes = [rte_self] + rtes

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

<<<<<<< HEAD
    def __init__(self, config_file):

        self.FSM = RouterFSM(self) 
        self.config_file = config_file 

        #router id
        self.router_id = None 
        #list input ports
        self.input_ports = []
        #set output ports, cost and output router id
        self.outputs = {}

        self.readable_ports = []

        #Dictionary of all input ports and corresponding socket objects.
        self.connections = {}  

        #Dictionary of routing table
        self.routing_table = {}

        ## STATES
        # Add string identifier to each class so that adding states becomes
        # self.FMS.addState(State(self.FSM))
        # Also think about defining states and transitions in RouterFSM class
        # to clean up router class.
        self.FSM.addState("StartUp", StartUp(self.FSM))
        self.FSM.addState("Waiting", Waiting(self.FSM))
        self.FSM.addState("ReadMessage", ReadMessage(self.FSM))
        self.FSM.addState("ValidateMessageHeader", 
                          ValidateMessageHeader(self.FSM))
        self.FSM.addState("ProcessAllRTEs", ProcessAllRTEs(self.FSM))
        self.FSM.addState("TriggerUpdate", TriggerUpdate(self.FSM))
        self.FSM.addState("EntryDeleteProcess", EntryDeleteProcess(self.FSM))


        ## TRANSITIONS
        self.FSM.addTransistion("toWaiting", Transistion("Waiting"))
        self.FSM.addTransistion("toReadMessage", Transistion("ReadMessage"))
        self.FSM.addTransistion("toValidateMessageHeader", 
                                Transistion("ValidateMessageHeader"))
        self.FSM.addTransistion("toProcessAllRTEs", 
                                Transistion("ProcessAllRTEs"))
        self.FSM.addTransistion("toTriggerUpdate", Transistion("TriggerUpdate"))
        self.FSM.addTransistion("toEntryDeleteProcess", 
                                Transistion("EntryDeleteProcess"))

        self.FSM.setState("StartUp")

    def execute(self):
        self.FSM.execute()

    def update(self):
        '''Send a message to all output ports''' 
        if self.outputs != {} and self.input_ports != []:
            sock = list(self.connections.values())[1]
            for output in list(self.outputs.keys()):
                message = 'Update From Router-ID: ' + str(self.router_id)
                sock.sendto(str.encode(message), (HOST, output))
                print("[" + time.strftime("%H:%M:%S") + "]: Message Sent To: " 
                      + str(output))


    def timer(self, period, function):
        '''Start a periodic timer which calls a specified function'''

        threading.Timer(period, self.timer, [period, function]).start()
        function()

    def start_timers(self):
        '''Start the various timers'''
        self.timer(5.0, self.update)

    def main_loop(self):
=======
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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0

        while True:
            self.execute()

<<<<<<< HEAD

if __name__ == "__main__":
    router = Router(str(sys.argv[-1])) 
    #router.print_router_info()    
    router.start_timers()
    router.main_loop()
    
=======
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
>>>>>>> d54d7185717c364ede2825ce8448ee590fb46cd0
