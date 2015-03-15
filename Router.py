'''
   Program that implements a routing deamon based on the RIP version 2 protocol.
   
   Authors:
       Andrew Dallow
       Dillon George 
'''
import configparser

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
                                                'id': int(output[2])}
            else:
                raise Exception('Invalid Outputs')
            
        return outputs_dict
    
    def print_router_info(self):
        '''Print information about the router'''
        print('Router ID: {}'.format(self.router_id))
        print('Input Ports: {}'.format(', '.join(str(x) for x in self.input_ports)))
        print('Outputs: ')
        for output in self.outputs:
            print (output)
            for values in self.outputs[output]:
                print (values, ':', self.outputs[output][values])        
        
        
def main():
    router = Router('router_1.txt')
    router.print_router_info()
    
main()
        
    