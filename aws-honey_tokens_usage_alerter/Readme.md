# Description
	Lambda function that periodically checks if AWS API calls have been made from honey tokens/fake users and alerts on Slack

# Requirements
- python3 libraries mentioned in requirements.txt
- role that has access to:
  - create Cloudwatch Log group and add logs to it
  - GetCredentialReport from IAM
  - GenerateCredentialReport from IAM
- incoming webhook to alert on Slack
- a list of users that act as the canary/honey tokens, embedded in your applications

# Execution
	Configure lambda to execute periodically