import json
import re
import operator
import logging

logging.basicConfig(filename='tfstate-compliance-checker.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger('tfstate-compliance-checker')

##########################
### Compliance Checker ###
##########################

class ComplianceChecker:
    '''
    This class is used to check the compliance of a Terraform state file against a compliance file.
    '''

    def __init__(self) -> None:
        '''
        Constructor for the ComplianceChecker class.
        '''
        pass

    def get_attribute_value(self, attributes, key):
        '''
        Returns the value of a key in a dictionary.
        param attributes: The attributes of the resources parsed from the Terraform state file.
        param key: The key of the resource to search for in the attributes dictionary.
        Returns: The value of the key in the dictionary.
        '''
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

    def check_rule(self, rule,attributes):
        '''
        Checks if a rule is valid.
        param rule: The rule to check.
        param attributes: The attributes of the resources parsed from the Terraform state file.
        Returns: A tuple containing a boolean indicating if the rule is valid and a string containing the error message if the rule is invalid.
        '''
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
        '''
        Checks if a condition is valid.
        param condition: The condition to check.
        param attributes: The attributes of the resources parsed from the Terraform state file.
        Returns: A tuple containing a boolean indicating if the condition is valid and a string containing the error message if the condition is invalid.
        '''
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
        '''
        Checks if a Terraform state file is compliant with a compliance file.
        param parsed_state: The parsed Terraform state file.
        param rule_path: The path to the compliance file.
        Returns: A dictionary containing the compliance result.
        '''
        rule = self.read_json(rule_path)
        provider = rule['provider']
        resource_type = rule['resource_type']
        condition = rule['condition']
        resources = parsed_state.get(f'{provider}.{resource_type}', [])
        
        if resources == []:
            result =  {
                'rule_name': rule['rule_name'],
                'compliance_level': rule['compliance_level'],
                'resource_type': resource_type,
                'resource_id': 'n/a',
                'compliance_status': True,
                'reason': 'Resource type is not found in the tfstate file.'
            }
            return result
        
        else:
            for resource in resources:
                ## TODO: Questionable solution.
                if isinstance(resource, list):
                    resource = resource[0]
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
        
    ##########################
    #### Helper Functions ####
    ##########################

    def get_operator_function(self, operator_str):
        '''
        Returns the operator function for a given operator string.
        param operator_str: The operator string to get the operator function for.
        Returns: The operator function.
        '''
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

    def read_json(self, path):
        '''
        Reads a JSON file and returns the data as a dictionary.
        '''
        with open(path, 'r') as file:
            result = json.load(file)
        return result
    
    def toString(self):
        '''
        Returns a string representation of the ComplianceChecker object.
        '''
        s1 = f"## ComplianceChecker Object ##\n"
        return s1