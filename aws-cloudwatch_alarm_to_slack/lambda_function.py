import json
import requests

#####Global Vars#######
default_vars_dict = {'slack_webhook': 'incoming_webhook'}
#######################

# sends data to slack

def lambda_handler(event, context):
    # TODO implement
    report_to_slack(event)
    return {
        "statusCode": 200,
        "body": json.dumps('GTS Lambda executed successfully!')
    }


def parsed_msg(msg_dict, appender=''):
    slack_msg_parsed = ''
    for key, val in msg_dict.items():
        if type(val) is not list and type(val) is not dict:
            slack_msg_parsed += '`{0}_{1}`: *{2}*\n'.format(appender, key, val)
        elif type(val) == list:
            slack_msg_parsed += parsed_msg(val[0], appender='{0}_{1}'.format(appender, key))
        elif type(val) == dict:
            slack_msg_parsed += parsed_msg(val, appender='{0}_{1}'.format(appender, key))
        else: print('Passing key: "{0}", value: "{1}" pair')
    return slack_msg_parsed


def report_to_slack(msg):
    if len(msg) == 0:
        print('Nothing to post to slack')
        return
    try:
        print('Preparing slack message request')
        slack_message_to_post = {
            "attachments" : [
                {
                    'color': '#ff0000',
                    # 'pretext': 'pretext_here',
                    'title': 'Cloudwatch Alarm',
                    # 'text': json.dumps(msg),
                    # 'text': json.dumps(msg['Records'][0]['Sns']),
                    'text': parsed_msg(msg['Records'][0]['Sns']),
                    # 'text': '',
                    'fallback': 'Cloudwatch alarm has triggered for "{0}"'.format(msg['Records'][0]['Sns']['Message']['Trigger']['Dimensions'][0]['value'])
                }
            ]
        }
        result = requests.post(default_vars_dict['slack_webhook'], data=json.dumps(slack_message_to_post), headers = {'Content-Type' :'application/json'})
        print('Posted to slack "{0}"'.format(result.text))
    except Exception as e:
        print('Exception "{0}" occurred in report_to_slack'.format(e))