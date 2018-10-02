# Description
	Our continuous efforts to improve our monitoring and threathunting capabilities in the AWS cloud
	Each folder/sub-project contains its own Readme.md

# Sub-Projects
## **aws-cloudwatch_alarm_to_rds**:
- Sends alarms from Cloudwatch to Slack via Lambda function
## **aws-role_credentials_leakage_monitor**:
- Monitors role credentials leakage from:
  - CloudTrail logs in ELK stack
  - Account ENIs and EIPs
## **aws-threatintel_vpc_flow_logs**: (in-progress)
- Gathers threat intelligence for bad reputed IPs from VPC flow logs
