# Description
	Sends Cloudwatch alarms to Slack using incoming webhook

# Requirements
	1. Lambda with the all the files in this project
	2. Lambda with permissions to Cloudwatch log group creation and put events in the log group
	3. Slack incoming webhook
	4. An SNS topic that receives Cloudwatch alarms

# Execution Flow
	Cloudwatch Alarms -> My SNS Topic -> Lambda

# Execution
	1. Lambda will be invoked once a Cloudwatch alarm is triggered