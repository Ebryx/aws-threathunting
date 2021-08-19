import argparse
import boto3
import csv

def get_elb_tag_name(tags):
        try:
                for tag in tags:
                        if tag['Key'] == 'name' or tag['Key'] == 'Name':
                                return tag['Value']
                return ''
        except Exception as e:
                print('[!] Error in get_elb_tag_name function with reason:', e)

def output_to_csv(res, csv_filename, op):
        try:
                if op == 'append':
                        with open(csv_filename, mode='a') as csv_file:
                                csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
                                for row in res:
                                        csv_writer.writerow(row)
                elif op == 'initiate':
                        with open(csv_filename, mode='w') as csv_file:
                                csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n').writerow(['Region', 'ELB Tag Name', 'ELB Name', 'ELB ARN', 'ELB Scheme', 'ELB Type', 'Logging Enabled', 'WAF Integrated'])
        except Exception as e:
                print('[!] Error in output_to_csv function with reason:', e)

def fetch_alb_nlb_status(aws_elbv2_client, aws_waf_client, csv_filename, region, only_noncompliant_results):
        try:
                res = [[region, get_elb_tag_name(aws_elbv2_client.describe_tags(ResourceArns=[x['LoadBalancerArn']])['TagDescriptions'][0]['Tags']), x['LoadBalancerName'], x['LoadBalancerArn'], x['Scheme'], x['Type'], aws_elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=x['LoadBalancerArn'])['Attributes'][0]['Value'] == 'true', (not((x['Type'] == 'network') or (x['Type'] == 'application' and not ('WebACLSummary' in aws_waf_client.get_web_acl_for_resource(ResourceArn=x['LoadBalancerArn']) and aws_waf_client.get_web_acl_for_resource(ResourceArn=x['LoadBalancerArn']).get('WebACLSummary')))))] for x in aws_elbv2_client.get_paginator('describe_load_balancers').paginate().build_full_result()['LoadBalancers'] if (not only_noncompliant_results) or ((aws_elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=x['LoadBalancerArn'])['Attributes'][0]['Key'] == 'access_logs.s3.enabled' and aws_elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=x['LoadBalancerArn'])['Attributes'][0]['Value'] == 'false') or (x['Scheme'] == 'internet-facing' and ((x['Type'] == 'application' and not ('WebACLSummary' in aws_waf_client.get_web_acl_for_resource(ResourceArn=x['LoadBalancerArn']) and aws_waf_client.get_web_acl_for_resource(ResourceArn=x['LoadBalancerArn']).get('WebACLSummary'))) or (x['Type'] == 'network'))))]
                res = res[:len(res)]
                output_to_csv(res, csv_filename, 'append')
        except Exception as e:
                print('[!] Error in fetch_alb_nlb_status function with reason:', e)

def fetch_clb_status(aws_elb_client, csv_filename, region, only_noncompliant_results):
        try:
                res = [[region, get_elb_tag_name(aws_elb_client.describe_tags(LoadBalancerNames=[x['LoadBalancerName']])['TagDescriptions'][0]['Tags']), x['LoadBalancerName'], '', x['Scheme'], 'classic', aws_elb_client.describe_load_balancer_attributes(LoadBalancerName=x['LoadBalancerName'])['LoadBalancerAttributes']['AccessLog']['Enabled'] == True, 'False'] for x in aws_elb_client.get_paginator('describe_load_balancers').paginate().build_full_result()['LoadBalancerDescriptions'] if (not only_noncompliant_results) or ((aws_elb_client.describe_load_balancer_attributes(LoadBalancerName=x['LoadBalancerName'])['LoadBalancerAttributes']['AccessLog']['Enabled'] == False) or (x['Scheme'] == 'internet-facing'))]
                output_to_csv(res, csv_filename, 'append')
        except Exception as e:
                print('[!] Error in fetch_clb_status function with reason:', e)

def main():
        try:
                parser = argparse.ArgumentParser()

                # variables / parameters start
                ### These can be modified depending upon requirements / scenarios
                profile_name = 'default'                # VARIABLE 1
                regions = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-south-1', 'eu-west-3', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']               # VARIABLE 2
                only_noncompliant_results = False               # VARIABLE 3
                csv_filename = 'elb_waf_logging_status.csv'             # VARIABLE 4
                # variables / parameters end

                parser.add_argument("-pn", "--profile_name", help="AWS profile name")
                parser.add_argument("-o", "--output", help="Filename for saving results with .csv extension")
                args = parser.parse_args()

                if args.profile_name:
                        profile_name = args.profile_name
                if args.output:
                        csv_filename = args.output

                print('### ELB WAF and Logging Status ###')
                output_to_csv([], csv_filename, 'initiate')

                for region in regions:
                        print('[i] Processing {} region results'.format(region))
                        fetch_alb_nlb_status(boto3.Session(profile_name=profile_name).client('elbv2', region_name=region), boto3.Session(profile_name=profile_name).client('waf-regional', region_name=region), csv_filename, region, only_noncompliant_results)
                        fetch_clb_status(boto3.Session(profile_name=profile_name).client('elb', region_name=region), csv_filename, region, only_noncompliant_results)
                print('[i] Execution Completed. Results saved to {} file'.format(csv_filename))

        except Exception as e:
                print('[!] Error in main function with reason:', e)

main()
