# Description
- Gathers all unique IPs from VPC flow logs
- Generates threat intel from OTX for gathered IPs
- Adds bad reputed IP records into the specified Elasticsearch index

# Requirements
- Install python libraries mentioned in requirements.txt
- Access to an Elasticsearch cluster

# Execution
- Can be executed on-demand/manually
- Can be executed periodically, as a cron job