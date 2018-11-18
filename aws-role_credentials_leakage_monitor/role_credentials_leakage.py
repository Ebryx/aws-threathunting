import sys
from datetime import datetime, timedelta
import os
from multiprocessing import Pool
from elasticsearch import Elasticsearch
from pprint import pprint
import time
import boto3
import json
import requests
import argparse


# Global Vars
ips = {'exist': [], 'do_not_exist': []}
args = ''
slack_final_message = ''
irrelevant_ips = ['AWS Internal'.lower(), 'amazonaws.com'.lower()]
es_queries = [
        # query that will be used to build assume role index
        {
          "_source": ["sourceIPAddress", "requestParameters", "responseElements.credentials.expiration", "event*"],
          "size": 10000,
          "query": {
            "bool": {
              "filter": {
                "range": {
                  "eventTime": {
                    "gte": "Insert Time here"
                  }
                }
              },
              "must": [
                {
                  "query_string": {
                    "query": "eventName: assumerole AND requestParameters.roleSessionName: i- AND (NOT errorCode)"
                  }
                }
              ]
            }
          }
        },
        # query that will be used to delete older records from assume_role_index
        {
          "query": {
            "bool": {
              "filter": {
                "range": {
                  "responseElements.credentials.expiration": {
                    "lte": "now"
                  }
                }
              }
            }
          }
        },
        # query that will be used to fetch all instance_ids that the assumed role calls were made from since last n minutes ago
        {
          "size": 0,
          "query": {
            "bool": {
              "filter": {
                "range": {
                  "eventTime": {
                    "gte": "Insert time here"
                  }
                }
              },
              "must": [
                {
                  # "query_string": {
                  #   "query": "userIdentity.type: assumedrole AND userIdentity.principalId: i-"
                  # }
                  "query_string": {
                    "query": "userIdentity.type: assumedrole AND userIdentity.principalId: *\\:i*"
                  }
                }
              ]
            }
          },
          "aggs": {
            "instance_ids": {
              "terms": {
                "field": "userIdentity.principalId.keyword",
                "size": 10000
              }
            }
          }
        },
        # query that will be used to fetch all IPs that the assumed role calls were made from since last n minutes ago
        {
          "size": 0,
          "query": {
            "bool": {
              "filter": {
                "range": {
                  "eventTime": {
                    "gte": "Insert time here"
                  }
                }
              },
              "must": [
                {
                  "query_string": {
                    "query": ""
                  }
                }
              ]
            }
          },
          "aggs": {
            "SrcIPs": {
              "terms": {
                "field": "sourceIPAddress.keyword",
                "size": 10000
              }
            }
          }
        }
]

default_vars_dict = {
    'total_threads': 5,
    'minutes': 15,
    'log_file': '{0}.log'.format(str(__file__)),
    'slack_message_to_post': {'attachments': []},
    'color': {
        'red': '#ff0000',
        'green': '#32cd32'
    }
}
#############


def setup_argparse():
    global args
    argparse_setup_completed_gracefully = False
    parser = argparse.ArgumentParser(
        description='''Requires Elasticsearch host and port''',
        epilog="""All's well that ends well.""",
        usage="""{0}.py -eh es_ip -ep es_port -eia some_es_index -eil some_es_index -sw slack_webhook -rn some_region_name -m some_minutes --es_max_reqeust_timeout some_seconds""".format(str(__file__)))
    parser.add_argument(
        '--es_host', '-eh',
        required=True,
        help='Elasticsearch host'
    )
    parser.add_argument(
        '--es_port', '-ep',
        required=True,
        help='Elasticsearch port'
    )
    parser.add_argument(
        '--es_index_for_assume_role_lookup', '-eia',
        required=True,
        help='Elasticsearch index that will be used to fetch records for assume role and build table'
    )
    parser.add_argument(
        '--es_index_lookup', '-eil',
        required=True,
        help='Elasticsearch index that will be used as the table for assume role calls'
    )
    parser.add_argument(
        '--total_threads', '-t',
        required=False,
        default=default_vars_dict['total_threads'],
        type=int,
        help='Number of threads to use'
    )
    parser.add_argument(
        '--region_name', '-rn',
        required=False,
        help='AWS region to use'
    )
    parser.add_argument(
        '--slack_webhook', '-sw',
        required=False,
        help='Slack webhook url'
    )
    parser.add_argument(
        '--es_max_request_timeout', '-emrt',
        required=False,
        type=int,
        help='Elasticsearch maximum request timeout in seconds'
    )
    parser.add_argument('--minutes', '-m',
        required=False,
        default=default_vars_dict['minutes'],
        type=int,
        help='Elasticsearch query that fetches all the IPs will fetch IPs since last this much minutes ago. Default is 15'
    )
    parser.add_argument(
        '--log_file', '-lf',
        required=False,
        default=default_vars_dict['log_file'],
        help='Log file'
    )
    args = parser.parse_args()

    argparse_setup_completed_gracefully = True
    print('Argparse setup complete')
    return argparse_setup_completed_gracefully


def log_msg(msg):
    try:
        with open(args.log_file, 'a') as o:
            mStr = str(msg)
            o.write(mStr + '\n\n')
            print('\n\n' + mStr)
    except Exception as e:
        print('Unable to write msg {0} to log file {1}'.format(msg, args.log_file))


def setup_log_file():
    with open(args.log_file, 'w') as o: pass


def go_back_minutes(minutes):
    dt = (datetime.utcnow() - timedelta(minutes=minutes))
    log_msg("datetime current is {2}. {0} minutes ago was {1}".format(minutes, dt, datetime.utcnow()))
    return dt


def modify_query(query, new_values, choice='time'):
    if choice == 'time':
        query['query']['bool']['filter']['range']['eventTime']['gte'] = new_values[0]
    elif choice == 'get_records':
        query['size'] = new_values[3]
        query['query']['bool']['filter']['range']['eventTime']['gte'] = new_values[2]
    elif choice == 'get_ip_for_assumed_role_api_calls':
        query['query']['bool']['filter']['range']['eventTime']['gte'] = new_values[0]
        query['query']['bool']['must'][0]['query_string']['query'] = new_values[1]
    # log_msg('Modified Query: "{0}"'.format(query))
    return query


def get_all_ips(es, query, go_back_minutes, index, es_max_request_timeout):
    result = None
    try:
        result = es.search(index=index, request_timeout=es_max_request_timeout, body=modify_query(query, [go_back_minutes]))['aggregations']['SrcIPs']['buckets']
        for ip in result:
            log_msg(ip)
    except Exception as e:
        log_msg('Exception {0} occurred in  get_all_ips'.format(e))

    return result


def setup_back_time():
    return go_back_minutes(args.minutes)


def get_raw_records_from_es(es, query, index, es_max_request_timeout):
    result = None
    try:
        result = es.search(index=index, body=query, request_timeout=es_max_request_timeout)['hits']['hits']
    except Exception as e:
        log_msg('Exception "{0}" occurred in get_raw_records_from_es'.format(e))
    return result


# def modify_assume_role_records(records):
#     try:
#         for idx, record in enumerate(records):
#             record = record['_source']
#             # Aug 16, 2018 3:10:05 AM
#             record['responseElements']['credentials']['expiration'] = datetime.strptime(record['responseElements']['credentials']['expiration'], '%b %d, %Y %H:%M:%S %p').strftime('%Y-%m-%dT%H:%M:%SZ')
#             record['responseElements']['credentials']['expiration'] = datetime.strptime(record['responseElements']['credentials']['expiration'], '%Y-%m-%dT%H:%M:%SZ')
#             record['eventTime'] = datetime.strptime(record['eventTime'], '%Y-%m-%dT%H:%M:%SZ')
#             pprint(record)
#             records[idx] = record
#             # log_msg('exp:{0}\ttime:{1}'.format(type(record['responseElements']['credentials']['expiration']), type(record['eventTime'])))

#         # a test record
#         # dt = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
#         # dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')
#         # records.append({'responseElements': {'credentials': {'expiration': dt}}})
#     except Exception as e:
#         log_msg('Exception "{0}" occurred in modify_assume_role_records'.format(e))
#     return records


# def send_records_to_es(es, index, records):
#     if records and len(records) > 0:
#         for record in records:
#             try:
#                 result = es.index(index=index, doc_type="sample_doc_type", body=record)
#                 log_msg('Record has been "{0}"'.format(result['result']))
#             except Exception as e:
#                 log_msg('Exception "{0}" occurred while sending record "{1}" to es'.format(e, record))


# def delete_expired_index_entries(es, index, query):
#     try:
#         result = es.delete_by_query(index=index, body=query)
#         log_msg('Records deletion result: \n"{0}"'.format(result))
#     except Exception as e:
#         log_msg('Exception "{0}" occurred in delete_expired_index_entries for query "{1}"'.format(e, query))


# def build_assumed_role_index(es, query, es_index_for_assume_role_lookup, minutes, es_index_lookup, query_to_delete_assume_role_records):
#     # delete_expired_index_entries(es, es_index_lookup, query_to_delete_assume_role_records)
#     send_records_to_es(
#         es,
#         es_index_lookup,
#         modify_assume_role_records(
#             get_raw_records_from_es(
#                 es,
#                 modify_query(
#                     query,
#                     [minutes],
#                     choice='time'
#                 ),
#                 es_index_for_assume_role_lookup
#             )
#         )
#     )


def get_ips_for_calls(es, query, index, instance_id, minutes, es_max_request_timeout):
    response = None
    try:
        response = es.search(index=index, request_timeout=es_max_request_timeout, body=modify_query(query, [minutes, 'userIdentity.type: assumedrole AND userIdentity.principalId: *{0}'.format(instance_id)], choice='get_ip_for_assumed_role_api_calls'))['aggregations']['SrcIPs']['buckets']
        for idx, record in enumerate(response):
                log_msg('Instance: {0}\tIP: {1}'.format(instance_id, record['key']))
                response[idx] = record['key']

    except Exception as e:
        log_msg('Exception "{0}" occurred in get_ips_for_calls when checking IPs for instance ID "{1}"'.format(e, instance_id))

    return response


def get_instance_id(value):
    # AROAIWRIXXXXXXXXXXXXXX:i-04XXXXXXXXXXXXXXX
    return str(value).split(':')[1].split('-')[1]


def report_to_slack(msg):
    try:
        if len(msg['attachments']) == 0:
            log_msg('Nothing to send to slack')
            return

        log_msg('Going to post the following message, json dump:')
        pprint(msg)

        log_msg('Going to post the following message defvars:')
        pprint(default_vars_dict['slack_message_to_post'])
        result = requests.post(args.slack_webhook, data=json.dumps(msg), headers = {'Content-Type' :'application/json'})
        log_msg('Posted to slack "{0}"'.format(result.text))
    except Exception as e:
            log_msg('Exception "{0}" occurred in report_to_slack'.format(e))


def remove_irrelevant_ips(ips):
    '''
    Takes an array of IPs. Removes certain IPs like 'AWS Internat' or '*.amazonaws.com'
    '''
    temp_ips = []
    for ip in ips:
        remove_ip = False
        for irrelevant_ip in irrelevant_ips:
            if irrelevant_ip.lower() in ip.lower():
                remove_ip = True
                break
        if remove_ip: continue
        else: temp_ips.append(ip)
    return temp_ips


def are_ips_in_same_account(cur_ips, all_account_ips):
    '''
    Check if each current IPs of the role belong to the same account IPs
    '''
    ips_not_in_same_account = []
    for ip in cur_ips:
        if ip not in all_account_ips:
            ips_not_in_same_account.append(ip)
    ret = True if len(ips_not_in_same_account) == 0 else False
    return ret, ips_not_in_same_account


def instance_id_is_valid(instance_id):
    ret = False
    try:
        int(str(instance_id), 16)
        ret = True
    except Exception as e:
        ret = False

    return ret


def instance_id_is_already_reported(instance_id, slack_msg):
    return instance_id in slack_msg


def find_credentials_leakage(es, query, index, minutes, query_for_ip, index_for_ip, all_account_ips, config_client, minutes2, region_name, es_max_request_timeout):
    slack_message_attachments = []
    global slack_final_message, default_vars_dict
    reported_count = 1
    try:
        response = es.search(index=index, body=query, request_timeout=es_max_request_timeout)['aggregations']['instance_ids']['buckets']
        for record in response:
            try:
                to_be_reported = False

                instance_id = get_instance_id(record['key'])

                if not instance_id_is_valid(instance_id):
                    log_msg('Found a something "{0}" against record "{1}" that\'s not a valid instance profile\nTherefore, continuing to next iteration'.format(instance_id, record))
                    continue

                # to cater alerts for duplicate instance IDs
                if instance_id_is_already_reported('i-{0}'.format(instance_id), json.dumps(slack_message_attachments)):
                    continue

                log_msg('Instance ID: {0}'.format(instance_id))

                ips = get_ips_for_calls(es, query_for_ip, index_for_ip, instance_id, minutes, es_max_request_timeout)
                temp_ips = remove_irrelevant_ips(ips)

                bool_more_than_1_ip = True if temp_ips and len(temp_ips) > 1 else False
                bool_ips_are_in_same_account, ips_not_in_same_account = are_ips_in_same_account(temp_ips, all_account_ips)


                instance_id = 'i-{0}'.format(instance_id)

                ### removing FPs
                if instance_id == 'i-083e244c7149db34f':
                    if len(temp_ips) == 2 and '10.0.56.56' in temp_ips and '52.212.123.222' in temp_ips:
                        continue

                if instance_id == 'i-07b5c4d81b69eba61':
                    if len(temp_ips) == 2 and '10.0.48.220' in temp_ips and '46.51.203.31' in temp_ips:
                        continue
                ################


                if not bool_ips_are_in_same_account:
                    config_result = check_ip_with_instance(config_client, instance_id, ips_not_in_same_account, minutes, datetime.utcnow())

                    # if any of the IPs was not previously attached with the instance and is not in the account
                    if not config_result['ret']:
                        to_be_reported = True
                        log_msg('==========Found IPs "{0}" for instance ID "{1}" that are not from the same account nor were they recently attached with the instance-----------'.format(config_result['ipList'], instance_id))
                        slack_message_attachments.append({
                                'color': default_vars_dict['color']['red'],
                                'title': 'Unknown IPs',
                                'pretext': 'Credential leaking instance: {0}'.format(instance_id),
                                'text': '`{2}.` Instance ID "`{0}`" role credentials were found to be making calls from IPs "{1}" that are *not in the same AWS account nor were found attached to the instance in the past {3} minutes*\n\n'.format(instance_id, ips_not_in_same_account, reported_count, minutes2).replace('\\', ''),
                                'fallback': 'Suspected credentials leakage detected for instance_id {0}'.format(instance_id)
                            })

                        reported_count += 1

                    else:
                        to_be_reported = True
                        log_msg('==========Found IPs "{0}" for instance ID "{1}" that are not from the same account-----------'.format(temp_ips, instance_id))
                        slack_message_attachments.append({
                                'color': default_vars_dict['color']['green'],
                                'title': 'Unknown IPs',
                                'pretext': 'Credential leaking instance: {0}'.format(instance_id),
                                'text': '`{2}.` Instance ID "`{0}`" role credentials were found to be making calls from IPs "{1}" that are *currently not in the same AWS account but the IPs were found attached with the instance in the past {3} minutes*.\n Possible *FP*.\nVisit link to further investigate: https://{4}.console.aws.amazon.com/config/home?region={4}}#/timeline/AWS::EC2::Instance/{0}}/configuration\n\n'.format(instance_id, ips_not_in_same_account, reported_count, minutes2, region_name).replace('\\', ''),
                                'fallback': 'Suspected credentials leakage detected for instance_id {0}'.format(instance_id)
                            })

                        reported_count += 1

                if len(temp_ips) > 1:
                    to_be_reported = True
                    log_msg('++++++++++Found multiple IPs "{0}" for instance ID "{1}" this record\n-------------'.format(temp_ips, instance_id))
                    slack_message_attachments.append({
                                'color': default_vars_dict['color']['red'],
                                'title': 'Multiple IPs',
                                'pretext': 'Credential leaking instance: {0}'.format(instance_id),
                                'text': '`{3}.` Instance ID "`{0}`" role credentials were found to be making calls from *multiple IPs ({2})* "{1}"\n\n'.format(instance_id, temp_ips, len(temp_ips), reported_count).replace('\\', ''),
                                'fallback': 'Suspected credentials leakage detected for instance_id {0}'.format(instance_id)
                            })
                    reported_count += 1
                else:
                    log_msg('@@@@@@@@@@No IP or Abnormality against instance ID "{0}"'.format(instance_id, ips))
                # slack_final_message['i-{0}'.format(instance_id)] = ips

            except Exception as e:
                log_msg('Exception "{0}" occurred in find_credentials_leakage while parsing record \n"{1}"'.format(e, record))

        default_vars_dict['slack_message_to_post']['attachments'].extend(slack_message_attachments)

    except Exception as e:
        log_msg('Exception "{0}" occurred in find_credentials_leakage for query "{1}"'.format(e, query))


def extract_ips_from_eips(mlist):
    results = []
    if mlist:
        for item in mlist:
            if 'PublicIp' in item:
                results.append(item['PublicIp'])
            if 'PrivateIpAddress' in item:
                results.append(item['PrivateIpAddress'])

    return list(set(results))


def extract_ips_from_enis(mlist):
    results = []
    if mlist:
        for item in mlist:
            try:
                if 'Ipv6Addresses' in item and len(item['Ipv6Addresses']) > 0:
                    for ipv6_addr in item['Ipv6Addresses']:
                        results.append(ipv6_addr['Ipv6Address'])

                if 'PrivateIpAddresses' in item and len(item['PrivateIpAddresses']) > 0:
                    for priv_ip_addr in item['PrivateIpAddresses']:
                        results.append(priv_ip_addr['PrivateIpAddress'])
                        if 'Association' in priv_ip_addr:
                            results.append(priv_ip_addr['Association']['PublicIp'])
            except Exception as e:
                log_msg('Exception "{0}" occurred in extract_ips_from_enis for item "{1}"'.format(e, item))

    return list(set(results))
    # return results


def get_all_account_ips_network_interfaces(client):
    results = []
    response = ''
    while True:
        if response and 'NextToken' in response:
            response = client.describe_network_interfaces(Filters=[{'Name': 'status', 'Values': ['available', 'in-use']}], NextToken=response['NextToken'])
        else:
            response = client.describe_network_interfaces(Filters=[{'Name': 'status', 'Values': ['available', 'in-use']}])

        if response and 'NetworkInterfaces' in response and len(response['NetworkInterfaces']) > 0:
            results = append_list_to_list(extract_ips_from_enis(response['NetworkInterfaces']), results)

        if 'NextToken' not in response: break

    return list(set(results))
    # return results


def get_all_account_ips_elastic_ips(client):
    results = []
    response = []
    while True:
        if response and 'NextToken' in response:
            response = client.describe_addresses(NextToken=response['NextToken'])
        else:
            response = client.describe_addresses()

        if response and 'Addresses' in response and len(response['Addresses']) > 0:
            results = append_list_to_list(extract_ips_from_eips(response['Addresses']), results)

        if 'NextToken' not in response: break
    return list(set(results))


def append_list_to_list(append_this_list, to_this_list):
    if append_this_list and len(append_this_list) > 0:
        to_this_list += append_this_list
    return to_this_list


def get_all_account_ips(client):
    all_ips = []
    try:
        all_ips = append_list_to_list(get_all_account_ips_network_interfaces(client), all_ips)
        all_ips = append_list_to_list(get_all_account_ips_elastic_ips(client), all_ips)
    except Exception as e:
        log_msg('Exception "{0}" occurred in get_all_account_ips'.format(e))
    return all_ips


def check_ip_with_instance(client, instance_id, ipList, earlierTime, laterTime):
    '''
    Checks the ipList provided against the last 20 known configurations of the instance that whether any of the IPs was attached with the instance previously
    '''
    ret = {
        'ipList': [],
        'ret': False
    }
    try:
        response = client.get_resource_config_history(
            resourceType='AWS::EC2::Instance',
            resourceId=instance_id,
            laterTime=laterTime,
            earlierTime=earlierTime,
            chronologicalOrder='Reverse',
            limit=50
        )
        print('Response:')
        pprint(response)

        # check if any of the IPs was previously attached with the instance
        if response:
            for ip in ipList:
                if ip not in str(response):
                    log_msg('+++++++++++++++++Found IP: "{0}" which was not previously attached with instance "{1}"'.format(ip, instance_id))
                    ret['ipList'].append(ip)

        # if any of the IP was not in use with the instance, return False, i.e: this is a TP
        if len(ret['ipList']) > 0:
            ret['ret'] = False
        else:
            ret['ret'] = True

    except Exception as e:
        log_msg('Exception "{0}" occurred in check_ip_with_instance for instance "{1}" for ipList "{2}"'.format(e, instance_id, ipList))

    return ret


def main():
    global slack_final_message, args
    es = Elasticsearch(['{0}:{1}'.format(args.es_host, args.es_port)])
    back_minutes = go_back_minutes(args.minutes)
    # build_assumed_role_index(
    #     es,
    #     es_queries[0],
    #     args.es_index_for_assume_role_lookup,
    #     args.minutes,
    #     args.es_index_lookup,
    #     es_queries[1]
    # )
    find_credentials_leakage(
        es,
        modify_query(
            es_queries[2],
            [args.minutes],
            choice='time'
        ),
        args.es_index_for_assume_role_lookup,
        back_minutes,
        es_queries[3],
        args.es_index_for_assume_role_lookup,
        get_all_account_ips(
            boto3.client(
                'ec2',
                region_name=args.region_name
            )
        ),
        boto3.client(
            'config',
            region_name=args.region_name
        ),
        args.minutes,
        args.region_name,
        args.es_max_request_timeout
    )

    log_msg('IPs that are found: "{0}"'.format(ips['exist']))
    log_msg('IPs that were not found: "{0}"'.format(ips['do_not_exist']))
    log_msg('Message to be sent on Slack: "{0}"'.format(slack_final_message))
    report_to_slack(default_vars_dict['slack_message_to_post'])


if __name__ == '__main__':
    setup_argparse()
    setup_log_file()
    mTime = [datetime.now(), 0]
    log_msg('Start Time: {0}'.format(mTime[0]))

    main()

    mTime[1] = datetime.now()
    log_msg('End Time: {0}'.format(mTime[1]))
    log_msg('Start Time: {0}'.format(mTime[0]))
    log_msg('End Time: {0}'.format(mTime[1]))
    log_msg('Time Diff: {0}'.format(mTime[1] - mTime[0]))
else:
    main()
