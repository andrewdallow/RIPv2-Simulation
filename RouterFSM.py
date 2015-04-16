'''
   Program that implements a routing deamon based on the RIP version 2 protocol.
   Can be run by: python3 Router.py <router_config_file> 
   
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

HOST = '127.0.0.1' #localhost
MAX_NUM_INPUTS = 15

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
        super().__init__(FSM)
        #super(StartUp, self).__init__(FSM)

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



    def get_outputs(self, config):
        '''Return a dictionary of outputs containing port, cost and destination
        router id from the Configuration file'''

        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]

        for output in outputs:
            is_valid_port = 1024 <= int(output[0]) <= 64000
            is_valid_cost = 1 <= int(output[1]) < 16
            is_valid_id = 1 <= int(output[2]) <= 64000
            if is_valid_port and is_valid_cost and is_valid_id:
                self.FSM.router.outputs[int(output[0])] = {
                                                'cost': int(output[1]), 
                                                'id': int(output[2])}
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


class Waiting(State):
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


class ProcessAllRTEs(State):
    def __init__(self, FSM):
        super(ProcessAllRTEs, self).__init__(FSM)

    def enter(self):
        pass

    def execute(self):
        pass

    def exit(self):
        pass


class TriggerUpdate(State):
    def __init__(self, FSM):
        super(TriggerUpdate, self).__init__(FSM)

    def enter(self):
        pass

    def execute(self):
        pass

    def exit(self):
        pass


class EntryDeleteProcess(State):
    def __init__(self, FSM):
        super(EntryDeleteProcess, self).__init__(FSM)
        
    def enter(self):
        pass
    
    def execute(self):
        pass
    
    def exit(self):
        pass 
    
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

    def transition(self):
        self.curState.exit()
        self.trans.execite()

    def execute(self):
        if self.trans:
            # Wrap this all in transiton method
            self.curState.exit()
            self.trans.execute()
            self.setState(self.trans.toState)
            self.curState.enter()
            self.trans = None
        self.curState.execute()


##===========================================================================
## IMPLEMENTATION


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

        while True:
            self.execute()


if __name__ == "__main__":
    router = Router(str(sys.argv[-1])) 
    #router.print_router_info()    
    router.start_timers()
    router.main_loop()
    
