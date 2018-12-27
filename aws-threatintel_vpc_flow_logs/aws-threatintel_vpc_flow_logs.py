import boto3
import sys
import os
from threading import Thread, BoundedSemaphore, Lock
from pprint import pprint
import gc
from datetime import datetime
import time, json
from lib.config import *
from elasticsearch import Elasticsearch
import ipaddress
from OTXv2 import OTXv2, IndicatorTypes
import requests


pts = str(sys.argv[0])
scriptName = sys.argv[0].split('/')[-1]
outDirPath = os.path.dirname(os.path.realpath(__file__)) + '/output'
outFileName = '{0}/{1}.txt'.format(outDirPath, scriptName)
if not os.path.exists(outDirPath):
    os.makedirs(outDirPath)
with open(outFileName, 'w') as o: pass


#outFileName = 'out-aws_threat_intel.py.txt'
#with open(outFileName, 'w') as o: pass

es = Elasticsearch (
    hosts=[{'host': elasticdomain['host'], 'port': elasticdomain['port']}]
)
index_name = 'threatintel-'+str(datetime.now()).split(' ')[0]
max_threads = 5
pool_sema = [BoundedSemaphore(value=max_threads), BoundedSemaphore(value=1)]
# source_ips = {}

source_ips = []
dst_ips = []

mips = {}
ips_list = []

index = {
    'ThreatIntel': []
}

logs = {}
vpcs = {
    'Vpcs': {}
}

flowlogs = {
    'FlowLogs': {},
}

client = boto3.client('ec2')
otx = OTXv2(otx_api_key)


def get_es_obj():
    try:
        return Elasticsearch (hosts=[{'host': elasticdomain['host'], 'port': elasticdomain['port']}])
    except Exception as e:
        print '[Exception occurred in get_es_obj]\n{0}'.format(str(e))
        return None


def slack_message(slack_text):
    ssense_webhook = "https://hooks.slack.com/services/B7BSR1MKJ/..."
    DATE_CONVERT = datetime.now()
    date_tweet = DATE_CONVERT.strftime("%m-%d-%Y|%H:%M:%S")

    slack = date_tweet + " EST" + ' | '  +'\n'+ slack_text
    slack_data = {'text': slack, "unfurl_links": 'true',
                  "unfurl_media": 'true'}
    response = requests.post(
        ssense_webhook, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    print response
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n\n%s'
            % (response.status_code, response.text)
        )


def check_for_uip(ips, log_group_name):
    global mips
    if not mips.has_key(log_group_name):
        mips[log_group_name] = ips
        print '----------------->>>>>>>>>>>Mips didn"t had Key'
        return True
    else:
        ret = False
        if ips[0] not in mips[log_group_name]:
            mips[log_group_name] += ips[0]
            # print '----------------->>>>>>>>>>>>HAS KEY'
            ret = True
        if ips[1] not in mips[log_group_name]:
            mips[log_group_name] += ips[1]
            ret = True
            # print '----------------->>>>>>>>>>>>HAS KEY'
        return ret


def get_public_IP(ip1, ip2):
    result = []
    try:
        if (not ipaddress.ip_address(ip1).is_private): result.append(ip1)
        if (not ipaddress.ip_address(ip2).is_private): result.append(ip2)
    except Exception as e:
        print '[Exception Occurred in get_public_IP]\n{0}'.format(str(e))
        return result


def get_threat_intel_details_push_to_es(event, vpc, flow_log, log_group_name):
    # unique IP check
    temp = event['message'].split()
    # if check_for_uip([temp[3], temp[4]], log_group_name):
    # if event['message'].split(' ')[3] not in source_ips or temp[4] not in dst_ips:
    #     print vpc, ' | ', flow_log, ' | ', log_group_name, ' | ', event['message'].split(' ')[3], ' | ', \
    #         event['message'].split(' ')[4]
    #
    #     source_ips.append(event['message'].split(' ')[3])
    #     dst_ips.append(temp[4])
    for ip in temp[3:5]:
        if ip not in ips_list and ipaddress.ip_address(ip).is_global:
            pool_sema[1].acquire()
            ips_list.append(ip)
            pool_sema[1].release()
            print vpc, ' | ', flow_log, ' | ', log_group_name, ' | ', ip
            #res = otx.get_indicator_details_full(IndicatorTypes.IPv4, event['message'].split(' ')[3])

            #logs['Vpcs'][vpc][flow_log][log_group_name]['Ips'].append(
            #    {event['message'].split(' ')[3]: res})

            mpush_to_es(event, vpc, flow_log, log_group_name,
                        res=otx.get_indicator_details_full(IndicatorTypes.IPv4, ip))


def mpush_to_es(event, vpc, flow_log, log_group_name, res=None):
    template = {
        'VpcId': vpc,
        'FlowLog': flow_log,
        'LogGroupName': log_group_name,
        'VpcLogMessage': event['message'],
        'SourceIp': event['message'].split(' ')[3],
        'DestinationIp': event['message'].split(' ')[4],
        'Status': event['message'].split(' ')[-2],
        '@timestamp': datetime.now().strftime('%Y-%m-%dT%H:%MZ'),
        'IOC': res if res is not None else ''
    }
    # index['ThreatIntel'].append(template)
    # es = get_es_obj()
    if es:
        es.index(index=index_name, doc_type='threatintel-doc', body=template, refresh=True)
    else:
        print "Couldn't load es object. Wasn't able to push results to es"


def gather_threat_intel(response_logs, vpc, flow_log, log_group_name):
    mThreads = []
    len_r = len(response_logs['events'])
    temp_count = 0
    for event in response_logs['events']:
        logs['Vpcs'][vpc][flow_log][log_group_name].update({'UniquePublicIps': 0})
        try:
            if (not ipaddress.ip_address(event['message'].split(' ')[3]).is_private) or \
                    (not ipaddress.ip_address(event['message'].split(' ')[4]).is_private):
#                if log_group_name == 'prodVPCFlowLogs':
#                    with open('out.txt', 'a') as o:
#                        mStr = 'prodVPCFlowLogs Event ---------->>>>>>>>>> {0}'.format(event)
#                        o.write(mStr + '\n')
                # # Adding to look for non mal IPS
                # if event['message'].split(' ')[3] in suspiciousIPs:
                #     slack_message(event['message'].split(' ')[3])

                if logs['Vpcs'][vpc][flow_log][log_group_name].has_key('Ips'):
                    mThreads.append(Thread(target=get_threat_intel_details_push_to_es,
                                           args=(event, vpc, flow_log, log_group_name)))
                    temp_count += 1
                    pool_sema[0].acquire()
                    mThreads[-1].start()
                    # get_threat_intel_details_push_to_es(event, vpc, flow_log, log_group_name)
                    pool_sema[0].release()
                else:
                    logs['Vpcs'][vpc][flow_log][log_group_name].update(
                        {'Ips': [event['message'].split(' ')[3]]})

        except Exception as e:
            print '[Exception Occurred in gatherthreat_intel\n]{0}: \n'.format(log_group_name), event['message'], ']\nException: [', str(e), ']'

            if 'does not appear to be an IPv4 or IPv6 address' in str(e):
                print 'Invalid Public IP: [', event['message'], ']\n'
            # else:
            #     print 'Trying again to retrieve ThreatIntel Reputation...'
            #     get_threat_intel_details_push_to_es(event, vpc, flow_log, log_group_name)

    for t in mThreads:
        t.join()

    logs['Vpcs'][vpc][flow_log][log_group_name].update({'EventsCount': len_r})


if __name__ == '__main__':

    current = datetime.utcnow()
    end_time = int(current.strftime("%s")) * 1000

    # For testing purposes using 5 minute parameter
    # start_time = end_time - 300000

    # start_time = end_time - 10800000       #   normal 180 minutes in milliseconds, normal is 60 minutes though.
    # Increasing this value because too many errors for Elasticsearch not being able to process such huge amount of logs
    start_time = end_time - 1800000         #   30 minutes in milliseconds
    # start_time = end_time - 900000          #   15 minutes in milliseconds
    #start_time = end_time - 300000          #   5 minutes in milliseconds


    print 'Start Time: {}'.format(start_time)
    print 'End Time: {}'.format(end_time)

    vpcs_list = client.describe_vpcs()
    for vpc in vpcs_list['Vpcs']:
        vpcs['Vpcs'].update({vpc['VpcId']: {}})

    logs = vpcs

    flowlogs = client.describe_flow_logs()
    for fl in flowlogs['FlowLogs']:
        try:
            logs['Vpcs'][fl['ResourceId']].update({fl['FlowLogId']: {fl['LogGroupName']: {}}})
        except:
            continue

    client_logs = boto3.client('logs')

    total_events = 0
    for vpc, value in logs['Vpcs'].iteritems():
        for flow_log, val in value.iteritems():
            for log_group_name, event in val.iteritems():
                print log_group_name
                count = 1
                response_logs = None
                while(count <= 3):
                    try:

                        # response_logs = client_logs.filter_log_events(
                        #         logGroupName=log_group_name,
                        #         startTime=start_time,
                        #         endTime=end_time,
                        #         limit=10000  # Its by default 10000
                        #     )

                        mNextToken = ''
                        len_events = len_old = len_cur = 0
                        token_old = ''
                        diff_old = 0
                        while mNextToken is not None:
                            if mNextToken == '':
                                # print 'NextToken is empty = ' + mNextToken
                                response_logs = client_logs.filter_log_events(
                                    logGroupName=log_group_name,
                                    startTime=start_time,
                                    endTime=end_time,
                                    limit=10000  # Its by default 10000
                                )
                                gather_threat_intel(response_logs, vpc, flow_log, log_group_name)
                                # response_logs = temp
                                len_old = len_cur = len(response_logs['events'])
                                len_events += len_cur
                                token_old = mNextToken = response_logs['nextToken'] if 'nextToken' in response_logs \
                                    else None

                                # De-allocating thousand of response_logs events and then calling garbage collector
                                # to free memory
                                response_logs = None
                                gc.collect()

                                continue
                            if mNextToken != '':
                                # print 'Putting next token ' + mNextToken
                                response_logs = client_logs.filter_log_events(
                                    logGroupName=log_group_name,
                                    startTime=start_time,
                                    endTime=end_time,
                                    nextToken=mNextToken,
                                    limit=10000  # Its by default 10000
                                )

                                # response_logs['events'] += (temp['events'])

                                len_cur = len(response_logs['events'])
                                len_events += len_cur

                                if 'nextToken' in response_logs and token_old != response_logs['nextToken']:
                                    token_old = mNextToken = response_logs['nextToken']
                                else: mNextToken = None

                                if mNextToken is not None:
                                    token_old = mNextToken
                                    # if len_events > 100000 or len_cur - 25 <= len_old:
                                    diff_cur = len_cur - len_old
                                    if diff_cur - diff_old < 500 or diff_cur == diff_old:
                                        print 'len_cur = {0}\nlen_old = {1}\nlen_total={2}'.format(len_cur, len_old,
                                                                                                   len_events)
                                        count = 10
                                        #  This if with break is required because if records are fetched too many a
                                        # times, RAM is totally consumed
                                        break
                                    else:
                                        diff_old = diff_cur
                                        len_old = len_cur

                                gather_threat_intel(response_logs, vpc, flow_log, log_group_name)

                                # De-allocating thousand of response_logs events and then calling garbage collector
                                # to free memory
                                response_logs = None
                                gc.collect()

                                # print 'Found next token ' + str(mNextToken)

                        with open(outFileName, 'a') as o:
                            temp_str = 'Total {0} Log Events for Log Group Name [{1}] are retrieved Successfully... ' \
                                .format(len_events, log_group_name)
                            o.write(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ') + '|' + temp_str + '\n')
                            print temp_str
                        break
                        # print 'Total Events fetched ----->' + str(len(response_logs['events']))

                            # print 'Total Events fetched ----->' + str(len(response_logs['events']))
                            # print (response_logs)




                        # break
                    except Exception as e:
                        print '\n[Exception Occurred{0}]: \n{1}'.format(log_group_name, str(e))
                        print 'Waiting 10 seconds and trying again to fetch...' \
                              '\nVPC: {}\nFlowLog: {}\nLogGroupName: {}\n'.format(vpc, flow_log, log_group_name)
                        count=+1
                        if(count > 3):
                            print '\n[Tried 3 Times] Failed to retrieve events against... ' \
                                '\nVPC: {}\nFlowLog: {}\nLogGroupName: {}'.format(vpc, flow_log, log_group_name)
                            exit()
                        time.sleep(10)
    #
                # for event in response_logs['events']:
                # # if log_group_name == 'prodVPCFlowLogs':
                #     #     with open('/tmp/prodvpcflowlogs.txt', 'a') as o: o.write(str(event) + '\n')
                #         # print 'ProdVPC Event ---------------->>>>>>>>>>>>>>>>' + str(event)
                #     # print event
                #     # print event['message'].split(' ')[3]
                #     logs['Vpcs'][vpc][flow_log][log_group_name].update({'UniquePublicIps': 0})
                #     try:
                #         if not ipaddress.ip_address(event['message'].split(' ')[3]).is_private:
                #             # # Adding to look for non mal IPS
                #             # if event['message'].split(' ')[3] in suspiciousIPs:
                #             #     slack_message(event['message'].split(' ')[3])
                #
                #             if logs['Vpcs'][vpc][flow_log][log_group_name].has_key('Ips'):
                #                 get_threat_intel_details_push_to_es(event, vpc, flow_log, log_group_name)
                #             else:
                #                 logs['Vpcs'][vpc][flow_log][log_group_name].update(
                #                     {'Ips': [event['message'].split(' ')[3]]})
                #
                #     except Exception as e:
                #         print '[Exception Occurred]: \n', event['message'], ']\nException: [', str(e), ']'
                #
                #         if 'does not appear to be an IPv4 or IPv6 address' in str(e):
                #             print 'Invalid Public IP: [', event['message'], ']\n'
                #         else:
                #             print 'Trying again to retrieve ThreatIntel Reputation...'
                #             get_threat_intel_details_push_to_es(event, vpc, flow_log, log_group_name)
                # logs['Vpcs'][vpc][flow_log][log_group_name].update({'EventsCount': len(response_logs['events'])})
    #
    # # print source_ips
    # #pprint (index)
    # # import json
    # # with open('logs/aws_threadintel_stats.json', 'w') as f:
    # #     json.dump(index, f)
