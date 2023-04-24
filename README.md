# Terraform State Compliance Checker

This Python application parses a Terraform state file and checks its compliance based on a predefined rule JSON file. The application includes a `TFState` class for parsing Terraform state files and a `ComplianceChecker` class for checking compliance.

## Features

- Parse Terraform state files and extract resources and providers.
- Check compliance of Terraform state files against a set of predefined rules in a JSON file.
- Log compliance checking process for debugging purposes.

## Requirements

- Python 3.7 or higher

## Usage

1. Ensure you have Python 3.7 or higher installed on your system.
2. Place your Terraform state file (e.g., `example.tfstate`) and your rule JSON file (e.g., `rules.json`) in the same directory as the script.
3. Adjust the main function in the script with the location of your Terraform state file and rule JSON file.
4. Run the script using the following command: `python your_script_name.py`
5. The script will generate an output JSON file (`output.json`) containing the compliance results.

## Classes

### TFState

This class is used to parse a Terraform state file and extract the resources and providers.

#### Attributes

- providers: A list of providers used in the Terraform state file.
- resources: A dictionary of resources used in the Terraform state file.
- statefile: The path to the Terraform state file.

### ComplianceChecker

This class is used to check the compliance of a Terraform state file against a compliance file.

## Example

### Input `rules.json`
```JSON
{
    "provider": "hashicorp/aws",
    "resource_type": "aws_s3_bucket",
    "rule_name": "S3 bucket must have default encryption",
    "compliance_level": "warning",
    "condition": {
      "operator": "and",
      "rules": [
        {
          "key": "server_side_encryption_configuration",
          "operator": "exists",
          "value": true
        },
        {
          "key": "server_side_encryption_configuration.0.rule",
          "operator": "contains",
          "value": {
            "apply_server_side_encryption_by_default": [
              {
                "kms_master_key_id": "",
                "sse_algorithm": "AES256"
              }
            ],
            "bucket_key_enabled": false
          }
        },
        {
          "key": "versioning.0.enabled",
          "operator": "matches",
          "value": false
        }
      ]
    }
  }  
```

The following example demonstrates how to use the `TFState` and `ComplianceChecker` classes to parse a Terraform state file and check its compliance:

```python
tfstate = TFState("example.tfstate")
cc = ComplianceChecker()
result = cc.check_compliance(tfstate.resources, "rules.json")
```

The `result` variable will contain a dictionary with the compliance results. You can then save it as a JSON file or use it for further processing.
```JSON
{
    "rule_name": "S3 bucket must have default encryption",
    "compliance_level": "warning",
    "resource_type": "aws_s3_bucket",
    "resource_id": "dummy-example-bucket",
    "compliance_status": true,
    "reason": ""
}
```