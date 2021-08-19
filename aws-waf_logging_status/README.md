# ELB Logging and WAF status

## Overview:
Python3 script for fetching the following results from an AWS account:
1. Logging status of ELBs
2. ALBs with WAF Integration Status
3. NLBs
4. CLBs

## Description:
This python3 script fetch the details of *elastic load balancers logging status*, *application load balancers with WAF integration status*, *network* and *classic load balancers*, from all the regions of an AWS account and output the results in a csv file.

## Pre-requisites

### Packages

Installation of the following utilities is a pre-requisite before running the script on a host:
- AWS CLI
- Python 3

### Environmental Configurations

- AWS CLI *'credentials'* file, under the .aws directory of the current user, needs to have valid AWS access keys having read permissions for load balancers and waf, for *default* profile name.
- AWS CLI *'config'* file, under the .aws directory of the current user, needs to contain the following configuration settings in order to avoid request throttling whereas the max_attempts argument can be modified based upon the need, for *default* profile name:
``` sh
	retry_mode=standard
	max_attempts=10
```

### Dependencies

The script has the following python library dependencies:
- boto3
- argparse
- csv

```sh
    pip install boto3
```

## Usage

Type the following command on command line or terminal in order to run the script, being in the same directory as the script.
```sh
	python elb_waf_logging_status.py --profile_name default --output output.csv
```
### Flags
- ***-pn*** OR ***--profile_name*** *(Optional)*: for providing AWS profile name as command line parameter.
- ***-o*** OR ***--output*** *(Optional)*: for specifying the output filename.

## Running Time
The time taken by the script to fetch, filter and save the results can take up to several minutes depending upon the number of load balancers in the AWS environment, e.g. around 15 minutes for 500 load balancers.

## Tweakable Parameters
Following paramters can be tweaked to change the course, scenario or requirements of the script, by changing the value of certain variables in the main function of this script:

  **Variable | Description**
- *profile_name*					| The AWS account profile name from '.aws/credentials' and '.aws/config' files that is used by this script to fetch results.
- *regions*						| The list of regions that are queried to gather all the relevant results from a single AWS account.
- *only_noncompliant_results*		| The flag to decide if all the result or only non-compliant results are to be saved as output. Its value can be either 'True' or 'False'.
- *csv_filename*					| The name of the output files where the results will be saved after execution of this script


## Output
The script will save the result output in a csv file with the following columns:

- Region
- ELB Tag Name
- ELB Name
- ELB ARN
- ELB Scheme
- ELB Type
- Logging Enabled
- WAF Integrated
