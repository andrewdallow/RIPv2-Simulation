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
from random import randint

HOST = '127.0.0.1' #localhost
BASE_TIMER = 5
MAX_METRIC = 16
ROUTE_TIMEOUT = BASE_TIMER * 6
DELETE_TIMEOUT = BASE_TIMER * 4

##===========================================================================
## TRANSITIONS
class Transistion():
    def __init__(self, toState):
        self.toState = toState
    
    def execute(self):
        pass

##===========================================================================
## STATES
class State():
    def __init__(self, FSM):
        self.FSM = FSM
    
    def enter(self):
        pass
    
    def execute(self):
        pass
    
    def exit(self):
        pass
    
    def printMessage(self, message):
        print("[" + time.strftime("%H:%M:%S") + "]: " + message)

class StartUp(State):
    def __init__(self, FSM):
        super(StartUp, self).__init__(FSM)
        
    def enter(self):
        pass        
    
    def execute(self):
        self.printMessage("Loading Configuration File: '" 
                          + self.FSM.router.config_file + "'")
        
        config = configparser.ConfigParser()
        config.read(self.FSM.router.config_file)        
        
        self.get_router_id(config)
        self.get_input_ports(config)
        self.get_outputs(config)
        
        self.setup_inputs()
        self.setupRoutingTable()
        self.FSM.router.printRoutingTable()
        
        self.FSM.toTransition("toWaiting") 
    
    def exit(self):
        self.printMessage("Router Setup Complete.")
    
    def get_router_id(self, config):
        '''Read the router id number from the configuration file'''
        
        if 1 <= int(config['Settings']['router-id']) <= 64000:
            self.FSM.router.router_id = int(config['Settings']['router-id'])
        else:
            raise Exception('Invalid Router ID Number')  
        
    def get_input_ports(self, config):
        '''Read and parse a list of input port numbers from the 
        configuration file'''        
        
        ports = config['Settings']['input-ports'].split(', ')        
        
        for port in ports:
            if 1024 <= int(port) <= 64000 and not(
                                    int(port) in self.FSM.router.input_ports):
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
    
    
    
    def get_outputs(self, config):
        '''Return a dictionary of outputs containing port, cost and destination
        router id from the Configuration file'''
        
        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]
                        
        for output in outputs:
            is_valid_port = 1024 <= int(output[0]) <= 64000 and not(
                                    int(output[0]) in self.FSM.router.outputs)
            is_valid_cost = 1 <= int(output[1]) < 16
            is_valid_id = 1 <= int(output[2]) <= 64000
            if is_valid_port and is_valid_cost and is_valid_id:
                self.FSM.router.outputs[int(output[2])] = {
                                                'metric': int(output[1]), 
                                                'port': int(output[0])}
            else:
                raise Exception('Invalid Outputs')
    
    
    def setup_inputs(self):
        
        #create socket for each input port
        for port in self.FSM.router.input_ports:
            try:
                self.FSM.router.connections[port] = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM)
                self.printMessage('Socket ' + str(port) + ' Created.')
            except socket.error as msg:
                print('Failed to create socket. Message: ' + str(msg))
                sys.exit()
                
            #bind port to socket
            try:
                self.FSM.router.connections[port].bind((HOST, port))
                self.printMessage('Socket ' + str(port) + ' Bind Complete.')
            except socket.error as msg:
                print('Failed to create socket. Message ' + str(msg))
                sys.exit()
    
    def setupRoutingTable(self):
        
        for output in self.FSM.router.outputs:
            self.FSM.router.routing_table[output] = RIPRouteEntry(
                            address=output, 
                            nexthop=self.FSM.router.router_id, 
                            metric=self.FSM.router.outputs[output]["metric"],
                            imported=True)            
        
        
        
class Waiting(State):
    def __init__(self, FSM):
        super(Waiting, self).__init__(FSM)
        
    def enter(self):
        self.printMessage("Entering idle state...")
        
    def execute(self):   
          
        readable, writable, exceptional = select.select(
                                        self.FSM.router.connections.values(), 
                                        [], [])        

        if readable:
            self.FSM.router.readable_ports = readable
            self.FSM.toTransition("toReadMessage")                       
    
    def exit(self):
        self.printMessage("Message Received")
        

class ReadMessage(State):
    def __init__(self, FSM):
        super(ReadMessage, self).__init__(FSM)        
        
    def enter(self):
        self.printMessage("Reading Messages...")
    
    def execute(self):
        
        for port in self.FSM.router.readable_ports:
            
            packet = RIPPacket(port.recvfrom(1024)[0])
            
            self.FSM.router.updateRoutingTable(packet)
        
        print(self.FSM.router.route_change)    
        if self.FSM.router.route_change:
                self.FSM.router.trigger_update()
        
        self.FSM.router.printRoutingTable()
        self.FSM.toTransition("toWaiting")      
        
    
    def exit(self):
        self.printMessage("Messages Read.")

##===========================================================================
## FINITE STATE MACHINE
class RouterFSM():
    def __init__(self, router):
        self.router = router
        self.states = {}
        self.transitions = {}
        self.curState = None
        self.trans = None
    
    def addTransistion(self, trandName, transition):
        self.transitions [trandName] = transition
        
    def addState(self, stateName, state):
        self.states[stateName] = state
        
    def setState(self, stateName):
        self.curState = self.states[stateName]
    
    def toTransition(self, toTrans):
        self.trans = self.transitions[toTrans]
        
    def execute(self):
        if self.trans:
            self.curState.exit()
            self.trans.execute()
            self.setState(self.trans.toState)
            self.curState.enter()
            self.trans = None
        self.curState.execute()
    

##===========================================================================
## IMPLEMENTATION

class RIPPacket:
    '''Class representing a RIP packet'''
    
    def __init__(self, data=None, header=None, rtes=None):
        
        if data:
            self._init_from_network(data)
            
        elif header and rtes:
            self._init_from_host(header, rtes)
        
        else:
            raise(ValueError)        
        
        
    def __repr__(self):
        return "RIPPacket: Command {}, Ver. {}, number of RTEs {}.".format(
                            self.header.cmd, self.header.ver, len(self.rtes))
        
    
    def _init_from_network(self, data):
        datalen = len(data)
        if datalen < RIPHeader.SIZE:
            raise(FormatException)
        
        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        
        if malformed_rtes:
            raise(FormatException)
        
        num_rtes = int((datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE)
        
        self.header = RIPHeader(data[0:RIPHeader.SIZE])
        
        self.rtes = []
        
        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE
        
        for i in range(num_rtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end], 
                                           src_id=self.header.src))
            
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE
            
        
        
    def _init_from_host(self, header, rtes):
        
        if header.ver != 2:
            raise(ValueError("Only Version 2 is supported."))
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
            raise(ValueError)
        
        
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
        return struct.pack(self.FORMAT, self.cmd, self.ver, self.src)
    
class RIPRouteEntry:
    '''Class representing a single RIP route entry (RTE)'''
    
    FORMAT = "!HHIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16
    
    def __init__(self, rawdata=None, src_id=None, afi=2, tag=0, address=None, 
                 nexthop=None, metric=None, imported=False):
        
        self.packed = None
        self.changed = False
        self.imported = imported        
        self.init_timeout()
        
        
        
        if rawdata and src_id != None:
            self._init_from_network(rawdata, src_id)
        elif afi != None and tag != None and address and nexthop and \
                                                                metric != None:
            self._init_from_host(afi, tag, address, nexthop, metric)
        else:
            raise(ValueError)
        
    def __repr__(self):
        template = "|{:^11}|{:^10}|{:^11}|{:^15}|{:^10}|"
        if self.timeout == None:
            
            return template.format(self.addr, self.metric, self.nexthop, 
                               self.changed, self.timeout)
            
        else:
            return template.format(self.addr, self.metric, self.nexthop, 
                               self.changed, self.timeout.strftime("%H:%M:%S"))        
        
    def _init_from_host(self, afi, tag, address, nexthop, metric):
        '''Init for data from host'''
        self.afi = afi
        self.tag = tag
        self.addr = address
        self.nexthop = nexthop
        self.metric = metric 
        
    def _init_from_network(self, rawdata, src_id):
        '''Init for data received from network'''
        self.packed = None
        rte = struct.unpack(self.FORMAT, rawdata)
        
        self.afi = rte[0]
        self.tag = rte[1]
        self.addr = rte[2]
        self.nexthop = rte[3]
        self.metric = rte[4]
        
        if self.nexthop == 0:
            self.nexthop = src_id
        
        #Validation
        if not(self.MIN_METRIC <= self.metric <= self.MAX_METRIC):
            raise(FormatException)
        
    
    def init_timeout(self):
        
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
        
    
    def setNexthop(self, nexthop):
        self.nexthop = nexthop
                
    def serialize(self):
        '''Pack entries into typical RIPv2 packet format for sending over the 
        network. '''
        return struct.pack(self.FORMAT, self.afi, self.tag, self.addr, 
                           self.nexthop, self.metric)


class FormatException(Exception):
    def __init__(self, message=""):
        self.message = message
          

class Router:
    
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
        
        self.route_change = False
        #Current Message being processed
        self.curMessage = ""
        
        ## STATES
        self.FSM.addState("StartUp", StartUp(self.FSM))
        self.FSM.addState("Waiting", Waiting(self.FSM))
        self.FSM.addState("ReadMessage", ReadMessage(self.FSM))
        
        
        ## TRANSITIONS              
        self.FSM.addTransistion("toWaiting", Transistion("Waiting"))
        self.FSM.addTransistion("toReadMessage", Transistion("ReadMessage"))
        
        self.FSM.setState("StartUp")
    
    def execute(self):
        self.FSM.execute() 
    
    
    def updateRoutingTable(self, packet):
        '''Update Routing table if new route info exist'''
        for rte in packet.rtes:
            if rte.addr != self.FSM.router.router_id:
                bestroute = self.routing_table.get(rte.addr)
                
                rte.setNexthop(packet.header.src)
                rte.metric = min(rte.metric 
                                 + self.outputs[packet.header.src]['metric'], 
                                 RIPRouteEntry.MAX_METRIC)
                
                if not bestroute:
                    if rte.metric == RIPRouteEntry.MAX_METRIC:
                        return
                    
                    rte.changed = True
                    self.route_change = True
                    self.routing_table[rte.addr] = rte
                    return
                else:
                    if rte.nexthop == bestroute.nexthop:
                        if bestroute.metric != rte.metric:
                            if bestroute.metric >= RIPRouteEntry.MAX_METRIC and \
                               rte.metric >= RIPRouteEntry.MAX_METRIC:
                                #garbage collection
                                bestroute.garbage = True                                
                            else:
                                self.updateRoute(bestroute, rte)
                        
                        elif not bestroute.garbage:
                            bestroute.init_timeout()
                            
                    elif rte.metric < bestroute.metric:
                        self.updateRoute(bestroute, rte)
        
          
    
    def updateRoute(self, bestroute, rte):
        '''Update an existing route entry with new route info'''   
                    
        bestroute.init_timeout()
        bestroute.garbage = False
        bestroute.changed = True
        bestroute.metric = rte.metric
        bestroute.nexthop = rte.nexthop
        self.route_change = True
    
        
    def printRoutingTable(self):
        print("+-----------+----------+-----------+---------------+----------+")
        print("|                      Routing Table                          |")
        print("+-----------+----------+-----------+---------------+----------+")
        print("|Router ID  |  Metric  |  NextHop  |  ChangedFlag  |  Timeout |")
        print("+-----------+----------+-----------+---------------+----------+")        
        
        
        for entry in self.routing_table:
            print(self.routing_table[entry])
            print("+-----------+----------+-----------+---------------+----------+")
           
    
    def trigger_update(self):
        '''Send Routing update for only the routes which have changed'''
        changed_rtes = []
        print("Sending Trigger update.")
        for rte in self.routing_table.values():
            if rte.changed:
                changed_rtes.append(rte)
                rte.changed = False
                
        self.route_change = False
        #send update with random delay between 1 and 5 seconds
        delay = randint(1, 5)
        threading.Timer(delay, self.update, [changed_rtes])
    
    def update(self, entries):
        '''Send a message to all output ports''' 
        if self.outputs != {} and self.input_ports != []:
            sock = list(self.connections.values())[1]
            local_header = RIPHeader(router_id=self.router_id)
            packet = RIPPacket(header=local_header, rtes=entries)
            
            for output in self.outputs:
                sock.sendto(packet.serialize(), 
                            (HOST, self.outputs[output]["port"]))
                
                print("[" + time.strftime("%H:%M:%S") 
                      + "]: Message Sent To Router: " + str(output))
                
           
 
        
    def check_timeout(self):
        print("Checking timeout...")
        if self.routing_table != {}:
            for rte in self.routing_table.values():
                if rte.timeout != None and \
                   (datetime.datetime.now() - rte.timeout).total_seconds() >= ROUTE_TIMEOUT:
                    rte.garbage = True
                    rte.changed = True
                    self.route_change = True
                    rte.metric = RIPRouteEntry.MAX_METRIC
                    rte.timeout = datetime.datetime.now()
                    self.printRoutingTable()
        
    
    def garbage_timer(self):
        print("Checking garbage timeout...")
        if self.routing_table != {}:
           for rte in self.routing_table.values():
                if rte.garbage:
                    if (datetime.datetime.now() - rte.timeout).total_seconds() >= DELETE_TIMEOUT:
                        rte.marked_for_delection = True
                    
    def garbage_collection(self):
        print("Collecting Garbage...")
        if self.routing_table != {}:
            delete_routes = []
            for rte in self.routing_table.values():
                if rte.marked_for_delection:
                    delete_routes.append(rte.addr)
            
            for entry in delete_routes:
                del self.routing_table[entry]
                self.printRoutingTable()
        
    
    def timer(self, period, function, param=None):
        '''Start a periodic timer which calls a specified function'''
        
        threading.Timer(period, self.timer, [period, function, param]).start()
        if param != None:
            function(param.values())
        else:
            function()
        
    def start_timers(self):
        '''Start the various timers'''
        self.timer(BASE_TIMER, self.update, param=self.routing_table)
        self.timer(BASE_TIMER, self.check_timeout)
        self.timer(BASE_TIMER, self.garbage_timer)
        self.timer(BASE_TIMER, self.garbage_collection)
    
    def main_loop(self):
        
        while True:
            self.execute()
                        
    
if __name__ == "__main__":
    router = Router(str(sys.argv[-1])) 
    #router.print_router_info()    
    router.start_timers()
    router.main_loop()
    