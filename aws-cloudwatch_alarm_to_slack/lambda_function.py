import json

import boto3
import requests


##### Global Vars #######
OPTIONS = {
    'slack_webhook': 'https://hooks.slack.com/services/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'
}
#########################


def parsed_msg(msg_dict, appender=str()):
    slack_msg_parsed = str()
    for key, val in msg_dict.items():
        try:
            
            # there was an issue where value against message key was being
            # interpreted as a string instead of dictionary
            # therefore, forcing the value to convert to dictionary
            if key == 'Message' and type(val) == str:
                val = json.loads(val)
            
            if type(val) is not list and type(val) is not dict:
                # me and my appender
                slack_msg_parsed += '`{0}_{1}`: *{2}*\n'.format(appender, key, val)
            elif type(val) == list:
                # for each item
                for idx, _ in enumerate(val):
                    if appender == '':
                        # me and id if I'm first/there's nothing before me
                        slack_msg_parsed += parsed_msg(
                            val[0], appender='{0}_{1}'.format(key, idx))
                    else:
                        # appender, me and id, id there's something before me
                        slack_msg_parsed += parsed_msg(
                            val[0], appender='{0}_{1}_{2}'.format(
                                appender, key, idx))

            elif type(val) == dict:
                # appender and me
                slack_msg_parsed += parsed_msg(
                    val, appender='{0}_{1}'.format(appender, key))
            else: print('Passing key: "{0}", value: "{1}" pair')

        except Exception as e:
            print('Exception "{0}" occurred in for loop in parsed_msg, '
                  'when parsing \nkey "{1}" and \nvalue {2}'.format(e, key, val))

    return slack_msg_parsed


def report_to_slack(msg):

    global OPTIONS

    try:
        print('Preparing slack message request')
        m_parsed_msg = parsed_msg(msg)
        print('Message has been parsed successfully')
        title_part = str()

        try: 
            title_part = msg['Records'][0]['Sns']['Subject']
        except Exception as e: 
            print('Exception "{0}" occurred while setting title_part'.format(e))

        slack_message_to_post = {'attachments': [
            {
                'color': '#ff0000',
                'title': title_part,
                'text': m_parsed_msg,
                'fallback': title_part
            }
        ]}

        print('Slack message post has been prepared: %s' % (slack_message_to_post))
        result = requests.post(
            OPTIONS['slack_webhook'],
            data=json.dumps(slack_message_to_post),
            headers={'Content-Type': 'application/json'})

        print('Alamr Name print: %s' % (title_part))
        print('Posted to slack "{0}"'.format(result.text))

    except Exception as e:
        print('Exception "{0}" occurred in report_to_slack ' \
              'when reporting msg \n"{1}"'.format(e, msg))


def get_cloudwatch_graph(event):

    metric = {
        'width': 600,
        'height': 400,
        'metrics': [
            ['AWS/RDS', 'NetworkTransmitThroughput',
             'DBInstanceIdentifier', 'o3-development']
        ]
    }

    boto

def lambda_handler(event, context):

    print('Event passed:\n%s' % (json.dumps(event, indent=2)))
    get_cloudwatch_graph(event)
    report_to_slack(event)

    return {
        "statusCode": 200,
        "body": json.dumps({'message': 'GTS Lambda executed successfully!'})
    }

if __name__ == "__main__":
    event = json.load(open('sample.json', 'r'))
    lambda_handler(event, dict())
