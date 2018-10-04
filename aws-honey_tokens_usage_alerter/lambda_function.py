import json
import requests
import boto3
import time
from datetime import datetime, timedelta

#####Global Vars#######
default_vars_dict = {
    'slack_webhook': 'incoming_webhook', 
    'honey_tokens': ['honey_user_1', 'honey_user_2'], 
    'alert_if_last_used_time_in_minutes_is_greater_than_this': 30, 
    'known_colums_with_date': ['password_last_used', 'password_last_changed', 'access_key_1_last_rotated', 'access_key_1_last_used_date', 'access_key_2_last_rotated', 'access_key_2_last_used_date', 'cert_2_last_rotated']
}
#######################

# sends data to slack

def lambda_handler(event, context):
    # TODO implement
    print('Passed Event: ')
    print(event)
    total_honeys = 1
    for key, val in get_honey_users(get_credential_report(boto3.client('iam'))).items():
        # report_to_slack('Honey Token/User "`{0}`" was last making AWS API calls at "*{1}*"'.format())
        report_to_slack(create_slack_message(key, val, total_honeys))
        total_honeys += 1
    return {
        "statusCode": 200,
        "body": json.dumps('GTS Lambda executed successfully!')
    }


def create_slack_message(user, attribs, honey_token_count):
    # title = 'Honey Token usage detected for User: "{0}"'.format(user)
    message = '`{0}`. Honey Token has been compromised for user: `{1}`\n'.format(honey_token_count, user)
    for attrib in attribs:
        for k, v in attrib.items():
            message += '`{0}`: *{1}*\n'.format(k, v)
    return message


def get_credential_report(client):
    '''
    try creating creds report until it is actually generated, only then download it
    '''
    response = None
    try:
        while True:
            response = client.generate_credential_report()
            print('Credential Report Status: "{0}"'.format(response['State']))
            if response['State'] == 'COMPLETE':
                break
            else: 
                print('Report hasn\'t been created yet. Sleeping for 10 seconds')
                time.sleep(10)

        response = client.get_credential_report()
        print('Credentials report generated at time "{0}":'.format(response['GeneratedTime']))
        print(response['Content'])
        return response['Content'].decode()
    except Exception as e:
        print('Exception "{0}" occurred in get_credential_report'.format(e))
        return response


def get_honey_users(report):
    # {1: 'password_last_used', 2: 'access_key_1_last_used'}
    column_num_and_name = {}
    
    # {'Username': [{'password_last_used': 'time'}, {'access_key_last_used': 'time'}]}
    honey_users_output = {}
    
    try:
        report_lines = report.split('\n')
        
        for idx, i in enumerate(report_lines[0].rstrip('\n').split(',')):
            if i in default_vars_dict['known_colums_with_date']:
                print('Column: "{0}"\tColumn number: "{1}"'.format(i, idx))
                column_num_and_name[idx] = i
        print('column_num_and_name: ')
        print(column_num_and_name)

        for line in report_lines[1:]:
            col_vals = line.rstrip('\n').split(',')
            # if user is a honey token
            if col_vals[0] in default_vars_dict['honey_tokens']:
                print('User "{0}" is a honey token'.format(col_vals[0]))
                # honey_users_output[col_vals[0]] = [{k: col_vals[v]} for k, v in column_num_and_name.items()]
                result = is_honey_token_compromised(col_vals, column_num_and_name)
                if result[0]:
                    honey_users_output.update(result[1])

                    
    except Exception as e:
        print('Exception "{0}" occurred in get_honey_users'.format(e))

    print('Honey users output: ')
    print(honey_users_output)
    return honey_users_output


def is_honey_token_compromised(col_vals, column_num_and_name):
    # {'User': [{'password_last_used': 'time'}, {'password_last_rotated': 'time'}]}
    mDictList = {}

    mList = []

    is_compromised = False

    try:
        # iof user is a honey token
        if col_vals[0] in default_vars_dict['honey_tokens']:
            print('Reconfirming that "{0}" is a honey_token'.format(col_vals[0]))
            for key, val in column_num_and_name.items():
                try:
                    td = (datetime.utcnow() - change_to_time(str(col_vals[key]))) /timedelta(minutes=1)
                    print('Time difference: "{0}"'.format(td))
                    if td < default_vars_dict['alert_if_last_used_time_in_minutes_is_greater_than_this']:

                        print('Timedelta "{0}" crosses threshold for key "{1}" and value "{2}"'.format(td, val, col_vals[key]))

                        is_compromised = True
                    else:
                        print('Timedelta "{0}" check failed for key "{1}" and value "{2}"'.format(td, val, col_vals[key]))
                except Exception as e:
                    print('Exception "{0}" occurred in timedifference for key "{1}" and value "{2}"'.format(e, val, col_vals[key]))

                mList.append({val: col_vals[key]})

        if is_compromised:
            mDictList[col_vals[0]] = mList

        # mDictList[col_vals[0]] = mList

        print('mDictList: ')
        print(mDictList)

    except Exception as e:
        print('Exception "{0}" occurred in is_honey_token_compromised for key'.format(e))

    return [is_compromised, mDictList]


def change_to_time(mTimeStr):
    return datetime.strptime(str(mTimeStr), '%Y-%m-%dT%H:%M:%S+00:00')


def report_to_slack(msg, title='Honey Token potential compromise detected'):
    try:
        print('Preparing slack message request')
        print('The message is as follows: \n{0}'.format(msg))
        slack_message_to_post = {
            "attachments" : [
                {
                    'color': '#ff0000',
                    'title': title,
                    'text': msg,
                    'fallback': 'Honey Token potential compromise detected'
                }
            ]
        }
        print('Slack message post has been prepared: ')
        print(slack_message_to_post)
        result = requests.post(default_vars_dict['slack_webhook'], data=json.dumps(slack_message_to_post), headers = {'Content-Type' :'application/json'})
        print('Posted to slack "{0}"'.format(result.text))
    except Exception as e:
        print('Exception "{0}" occurred in report_to_slack when reporting msg \n"{1}"'.format(e, msg))