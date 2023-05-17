import json
import logging

from state_parser import TFState
from compliance_checker import ComplianceChecker

logging.basicConfig(filename='tfstate-compliance.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s %(message)s')
logger = logging.getLogger('tfstate-compliance')

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
