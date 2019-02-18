import json
import requests
from pprint import pprint

#####Global Vars#######
default_vars_dict = {
        'slack_webhook': 'https://hooks.slack.com/services/.../...'
    }
#######################

# sends data to slack

def lambda_handler(event, context):
    # TODO implement
    print('Passed Event: ')
    pprint(event)
    report_to_slack(event)
    return {
        "statusCode": 200,
        "body": json.dumps('GTS Lambda executed successfully!')
    }


def parsed_msg(msg_dict, appender=''):
    slack_msg_parsed = ''
    for key, val in msg_dict.items():
        try:
            
            # there was an issue where value against message key was being interpreted as a string instead of dictionary
            # therefore, forcing the value to convert to dictionary
            if key == 'Message' and type(val) == str:
                val = json.loads(val)
            
            if type(val) is not list and type(val) is not dict:
                # me and my appender
                slack_msg_parsed += '`{0}_{1}`: *{2}*\n'.format(appender, key, val)
            elif type(val) == list:
                # for each item
                for idx, item in enumerate(val):
                    if appender == '':
                        # me and id if I'm first/there's nothing before me
                        slack_msg_parsed += parsed_msg(val[0], appender='{0}_{1}'.format(key, idx))
                    else:
                        # appender, me and id, id there's something before me
                        slack_msg_parsed += parsed_msg(val[0], appender='{0}_{1}_{2}'.format(appender, key, idx))
            elif type(val) == dict:
                # appender and me
                slack_msg_parsed += parsed_msg(val, appender='{0}_{1}'.format(appender, key))
            else: print('Passing key: "{0}", value: "{1}" pair')
        except Exception as e:
            print('Exception "{0}" occurred in for loop in parsed_msg, when parsing \nkey "{1}" and \nvalue {2}'.format(e, key, val))
    return slack_msg_parsed


def report_to_slack(msg):
    try:
        print('Preparing slack message request')
        m_parsed_msg = parsed_msg(msg)
        # print('The parsed message is as follows: \n{0}'.format(m_parsed_msg))
        print('Message has been parsed successfully')
        title_part = ''
        fallback_part = ''
        try: 
            title_part = msg['Records'][0]['Sns']['Subject']
        except Exception as e: 
            print('Exception "{0}" occurred while setting title_part'.format(e))
        slack_message_to_post = {
            "attachments" : [
                {
                    'color': '#ff0000',
                    # 'pretext': 'pretext_here',
                    'title': title_part,
                    # 'text': json.dumps(msg),
                    # 'text': json.dumps(msg['Records'][0]['Sns']),
                    'text': m_parsed_msg,
                    # 'text': '',
                    # 'fallback': 'Testing'
                    'fallback': title_part
                }
            ]
        }
        print('Slack message post has been prepared: ')
        print(slack_message_to_post)
        result = requests.post(default_vars_dict['slack_webhook'], data=json.dumps(slack_message_to_post), headers = {'Content-Type' :'application/json'})
        print('Alamr Name print:')
        print(title_part)
        print('Posted to slack "{0}"'.format(result.text))
    except Exception as e:
        print('Exception "{0}" occurred in report_to_slack when reporting msg \n"{1}"'.format(e, msg))