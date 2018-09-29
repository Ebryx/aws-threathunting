# Description:
	A script that runs on the Cloudtrail logs in Elasticsearch
	Determines, whether the role credentials setup on an EC2 instance have been compromised

# Requirements:
	Install python3 libraries mentioned in 'requirements.txt'
	Require access to Elasticsearch cluster
	Setup an incoming webhook for a Slack channel
	Requires a role or AWS Access key with IAM permission to: 
		ec2:DescribeNetworkInterfaces
		ec2:DescribeAddresses

# Execution:
	Point the script to the CloudTrail Index in Elasticsearch cluster to execute it
	Pass Slack incoming webhook to the script
	Read '-h' options of the script for execution examples