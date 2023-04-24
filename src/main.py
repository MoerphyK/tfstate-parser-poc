import json
import re
import operator
import logging

logging.basicConfig(filename='tfstate-compliance.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger('tfstate-compliance')

####################
### State Parser ###
####################
class TFState:
    
    def __init__(self, path):
        self.providers = []
        
        tfstate_data = self.read_json(path)
        resources_list = tfstate_data['resources']
    
        self.resources = self.parse_resources(resources_list)
        self.statefile = path

    def toString(self):
        s1 = f"## TFState Object ##\n# Statefile #\n{self.statefile}\n\n# Providers #\n{self.providers}\n\n# Resources #\n{self.resources}\n"
        return s1
        
    def read_json(self, path):
        with open(path, 'r') as file:
            result = json.load(file)
        return result

    def parse_provider(self, provider_string):
        # Extract the provider name from the string
        match = re.search(r'provider\["(.+?)/(.+?)"\]', provider_string)
        if match:
            if match.group(2) not in self.providers:
                self.providers.append(match.group(2))
            return match.group(2)
        return "unknown"

    def parse_resources(self, resources_list):
        resources = {}
        for resource in resources_list:
            resource_type = resource['type']
            # resource_name = resource['name']
            provider = self.parse_provider(resource['provider'])
            resource_key = f"{provider}.{resource_type}"
            # resource_key = f"{provider}.{resource_type}.{resource_name}"
            resource_instances = resource['instances']
            if resource_key not in resources:
                resources[resource_key] = resource_instances
            else:
                resources[resource_key].append(resource_instances)
        return resources

##########################
### Compliance Checker ###
##########################

class ComplianceChecker:

    def __init__(self) -> None:
        pass

    def read_json(self, path):
        with open(path, 'r') as file:
            result = json.load(file)
        return result

    def get_attribute_value(self, attributes, key):
        keys = key.split('.')
        value = attributes.get(keys[0])

        for k in keys[1:]:
            if isinstance(value, list):
                if k.isdigit() and int(k) < len(value):
                    value = value[int(k)]
                else:
                    value = None
            elif isinstance(value, dict):
                value = value.get(k)
            else:
                value = None
            if value is None:
                break

        return value

    def get_operator_function(self, operator_str):
        operator_map = {
            'eq': operator.eq,
            'neq': operator.ne,
            'contains': operator.contains,
            'not_contains': lambda a, b: not operator.contains(a, b),
            'exists': lambda a, b: isinstance(a, str) or bool(a) == b, ## Does not work with NullType
            'not_exists': lambda a, b: isinstance(a, str) or bool(a) != b, ## Does not work with NullType
            'matches': lambda a, b: bool(re.match(str(b), str(a))), ## Does not work with dict
            'not_matches': lambda a, b: not bool(re.match(str(b), str(a))), ## Does not work with dict
            'and': all, ## Works with list of bools
            'or': any ## Works with list of bools
        }
        return operator_map.get(operator_str)

    def check_rule(self, rule,attributes):
        logger.info(f'## Called check_rule ##\n# Attributes:\n{attributes}\n# Rule:\n{rule}')
        # Extract infos from rule
        operator_str = rule.get('operator', '')
        key = rule.get('key', '')
        value = rule.get('value')

        # Get operator
        operator_fn = self.get_operator_function(operator_str)
        logger.info(f'check_rule - operator: {operator_str}')
        # Check rule inputs validity
        if not key or not operator_str:
            return False, 'Invalid rule'

        actual_value = self.get_attribute_value(attributes, key)

        if operator_fn is None:
            return False, f'Invalid operator: {operator_str}'
        elif actual_value == None and operator_str == 'contains':
            return False, "Key can't be found in resource attributes."
        elif actual_value == None and operator_str == 'not_contains':
            return True, "Key can't be found in resource attributes."

        return operator_fn(actual_value, value),''

    def check_condition(self, attributes, condition):
        logger.info(f'## Called check_condition ##\n# Attributes:\n{attributes}\n# Condition:\n{condition}')
        operator_fn = None

        for key, value in condition.items():
            if key == 'operator':
                operator_fn = self.get_operator_function(value)
                logger.info(f'check_condition - operator: {value}')
            elif key == 'rules':
                rules = value

        if operator_fn is None:
            return False, 'Invalid operator'

        rule_results = []
        for rule in rules:
            result,_ = self.check_rule(rule,attributes)
            rule_results.append(result)

        logger.info(f'check_condition - results: {rule_results}')
        return operator_fn(rule_results), ''

    def check_compliance(self, parsed_state, rule_path):
        rule = self.read_json(rule_path)
        provider = rule['provider']
        resource_type = rule['resource_type']
        condition = rule['condition']
        resources = parsed_state.get(f'{provider}.{resource_type}', [])

        for resource in resources:
            attributes = resource.get('attributes', {})
            is_compliant, reason = self.check_condition(attributes, condition)

        result = {
            'rule_name': rule['rule_name'],
            'compliance_level': rule['compliance_level'],
            'resource_type': resource_type,
            'resource_id': attributes.get('id', ''),
            'compliance_status': is_compliant,
            'reason': reason
        }
        
        return result

def main():
    ### TODO: Validation of Input
    tfstate = TFState("moduleinmodule.tfstate")
    cc = ComplianceChecker()
    result = cc.check_compliance(tfstate.resources, "rules.json")
    
    return result

if __name__ == "__main__":
    result = main()
    with open("output.json", "w") as outfile:
        json.dump(result, outfile)