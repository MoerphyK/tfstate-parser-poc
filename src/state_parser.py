import json
import re
import logging

logging.basicConfig(filename='tfstate-state-parser.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger('tfstate-state-parser')

####################
### State Parser ###
####################

class TFState:
    ''' 
    This class is used to parse a Terraform state file and extract the resources and providers. 
    Attributes:
        providers: A list of providers used in the Terraform state file.
        resources: A dictionary of resources used in the Terraform state file.
        statefile: The path to the Terraform state file.
    '''
    
    def __init__(self, path=None, state_dict=None):
        '''
        Constructor for the TFState class.
        param path: The path to the Terraform state file.
        param state_dict: The state passed as a dictonary.
        '''
        self.providers = []
        tfstate_data = {}
        if path is None and state_dict is None:
            logger.error('TFState object could not be created. No path or state_dict has been passed.')
            raise Exception('TFState object could not be created. No path or state_dict has been passed.')
        if path is not None and state_dict is not None:
            raise Exception('TFState object could not be created. Both path and state_dict have been passed. Choose one.')
        elif path is None and state_dict is not None:
            tfstate_data = state_dict
            self.statefile = 'Received dictionary'
        elif path is not None and state_dict is None:
            tfstate_data = self.read_json(path)
            self.statefile = path
        resources_list = tfstate_data['resources']
    
        self.resources = self.parse_resources(resources_list)

    def toString(self):
        '''
        Returns a string representation of the TFState object.
        '''
        s1 = f"## TFState Object ##\n# Statefile #\n{self.statefile}\n\n# Providers #\n{self.providers}\n\n# Resources #\n{self.resources}\n"
        return s1
        
    def read_json(self, path):
        '''
        Reads a JSON file and returns the data as a dictionary.
        '''
        with open(path, 'r') as file:
            result = json.load(file)
        return result

    def parse_provider(self, provider_string):
        '''
        Extracts the provider name from a string.
        param provider_string: The string to extract the provider name from and add to the providers list.
        Returns: The provider name.
        '''
        # Extract the provider name from the string
        match = re.search(r'provider\["(.+?)/(.+?)"\]', provider_string)
        if match:
            if match.group(2) not in self.providers:
                self.providers.append(match.group(2))
            return match.group(2)
        return "unknown"

    def parse_resources(self, resources_list):
        '''
        Parses the resources list and returns a dictionary of resources.
        param resources_list: The list of resources to parse.
        Returns: A dictionary of resources.
        '''
        resources = {}
        for resource in resources_list:
            resource_type = resource['type']
            provider = self.parse_provider(resource['provider'])
            resource_key = f"{provider}.{resource_type}"
            resource_instances = resource['instances']
            if resource_key not in resources:
                resources[resource_key] = resource_instances
            else:
                resources[resource_key].append(resource_instances)
        return resources