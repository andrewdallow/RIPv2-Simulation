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

class Router:

    def __init__(self, config_file):

        config = configparser.ConfigParser()
        config.read(config_file) 

        #set router id and check for errors
        self.router_id = self.get_router_id(config)

        #set input ports and check for errors
        self.input_ports = self.get_input_ports(config)

        #set output ports, cost and output router id
        self.outputs = self.get_outputs(config)

        #Dictionary of all input ports and corresponding socket objects.
        self.connections = {}

        #Dictionary of routing table
        self.routing_table = {}

    def get_router_id(self, config):
        '''Read and return the router id number from the configuration file'''

        if 1 <= int(config['Settings']['router-id']) <= 64000:
            id = int(config['Settings']['router-id'])
        else:
            raise Exception('Invalid Router ID Number')  

        return id


    def get_input_ports(self, config):
        '''Read parse and return a list of input port numbers from the 
        configuration file'''

        input_ports = []
        ports = config['Settings']['input-ports'].split(', ')

        for port in ports:
            if 1024 <= int(port) <= 64000:
                input_ports.append(int(port))
            else:
                raise Exception('Invalid Port Number')

        return input_ports

    def get_outputs(self, config):
        '''Return a dictionary of outputs containing port, cost and destination
        router id from the Configuration file'''
        outputs_dict = {}
        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]


        for output in outputs:
            is_valid_port = 1024 <= int(output[0]) <= 64000
            is_valid_cost = 1 <= int(output[1]) < 16
            is_valid_id = 1 <= int(output[2]) <= 64000

            if is_valid_port and is_valid_cost and is_valid_id:
                outputs_dict[int(output[0])] = {'cost': int(output[1]),
                                                'id'  : int(output[2])}
            else:
                raise Exception('Invalid Outputs')

        return outputs_dict


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

    def setup_inputs(self):

        #create socket for each input port
        for port in self.input_ports:
            try:
                self.connections[port] = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM)
                print('Socket ' + str(port) + ' Connected')
            except socket.error as msg:
                print('Failed to create socket. Message: ' + str(msg))
                sys.exit()

            #bind port to socket
            try:
                self.connections[port].bind((HOST, port))
                print('Socket ' + str(port) + ' Bind Complete')
            except socket.error as msg:
                print('Failed to create socket. Message ' + str(msg))
                sys.exit()


    def update(self):
        '''Send a message to all output ports'''
        sock = list(self.connections.values())[1]
        for output in list(self.outputs.keys()):
            message = 'Update From Router-ID:' + str(self.router_id)
            sock.sendto(str.encode(message), (HOST, output))
            print('Message Send: ' + str(output))

    def timer(self, period, function):
        '''Start a periodic timer which calls a specified function'''

        threading.Timer(period, self.timer, [period, function]).start()
        function()

    def start_timers(self):
        '''Start the various timers'''
        self.timer(5.0, self.update)

    def main_loop(self):
        '''Main loop of Router which listens to the input ports and processes
        data received from those ports using select(). [Currently only prints
        the received data.]''' 

        inputs = self.connections.values()
        while True:
            readable, writable, exceptional = select.select(inputs,[],[])

            for port in readable:
                received = port.recvfrom(1024)
                data = received[0].decode('utf-8')
                addr = received[1]

                #Process received data
                if data:
                    print('Message[' + addr[0] + ':'
                          + str(port.getsockname()[1]) + '] - ' + data.strip())



if __name__ == '__main__':
    router = Router(str(sys.argv[-1])) 
    router.print_router_info()
    router.setup_inputs()
    router.start_timers()
    router.main_loop()


