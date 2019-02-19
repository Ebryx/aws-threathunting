import os
import json
import time
import logging

import boto3
import requests
from elasticsearch import Elasticsearch


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
logger.addHandler(handler)


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
                slack_msg_parsed += '`{0}_{1}`: *{2}*\n'.format(
                    appender, key, val)
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
            else:
                logger.info('Passing key: `{0}`, value: '
                            '`{1}` pair'.format(key, val))

        except Exception as e:
            logger.info('Exception {0} occurred in for loop in parsed_msg, '
                        'when parsing key `{1}` and value `{2}`'.format(
                            e, key, val))

    return slack_msg_parsed


def report_to_slack(msg, images):

    try:
        m_parsed_msg = parsed_msg(msg)
        logger.info('Message has been parsed successfully.')
        title_part = str()

        try:
            title_part = msg['Records'][0]['Sns']['Subject']
        except Exception as e:
            logger.error(e)

        attachments = [{
            'color': '#ff0000',
            'title': 'SAMPLE via python\n' + title_part,
            'text': m_parsed_msg,
            'fallback': title_part
        }]
        attachments.extend([{
            'color': '#ff0000',
            'footer': img['title'],
            'author_name': 'Graph Image',
            'author_link': img['url'],
            'image_url': img['url']
        } for img in images])

        slack_message_to_post = {'attachments': attachments}

        logger.debug('Slack message post \n: %s' % (slack_message_to_post))
        result = requests.post(
            os.environ.get('SLACK_WEBHOOK'),
            data=json.dumps(slack_message_to_post),
            headers={'Content-Type': 'application/json'})

        logger.info(str())
        logger.info('Alarm Name: %s', title_part)
        logger.info('Posted to slack: %s', result.text)

    except Exception as e:
        logger.error(e)


def get_cloudwatch_graph(event):

    try:
        trigger = event['Records'][0]['Sns']['Message']['Trigger']
    except KeyError:
        trigger = dict()

    if not trigger:
        logger.info('No trigger found in event.')
        return

    metric = [trigger['Namespace'], trigger['MetricName']]
    try:
        alarm = event['Records'][0]['Sns']['Message']['AlarmName']
    except KeyError:
        alarm = None

    target_dims = {'DBInstanceIdentifier': str()}
    if trigger['Dimensions']:
        for dim in trigger['Dimensions']:
            if dim['name'] in target_dims:
                target_dims[dim['name']] = dim['value']

            metric.extend([dim['name'], dim['value']])

    id_string = alarm + '/' if alarm else str()
    id_string += '/'.join(target_dims.values())

    images = list()
    cloudwatch = boto3.client('cloudwatch')
    variations = [
        {
            'start': '-PT3H',
            'title': 'Last 3 Hours (%s)' % (id_string),
            'period': 60 * 5,
            'width': 800,
            'height': 200
        },
        {
            'start': '-PT24H',
            'title': 'Last 24 Hours (%s)' % (id_string),
            'period': 60 * 10,
            'width': 1000,
            'height': 230
        },
        {
            'start': '-PT168H',
            'title': 'Last 7 Days (%s)' % (id_string),
            'period': 60 * 20,
            'width': 1600,
            'height': 320
        }
    ]

    for option in variations:
        widget = {
            'width': option['width'],
            'height': option['height'],
            'start': option['start'],
            'metrics': [metric],
            'title': option['title'],
            'period': option['period']
        }

        res = cloudwatch.get_metric_widget_image(
            MetricWidget=json.dumps(widget))

        images.append({
            'title': option['title'],
            'data': res.get('MetricWidgetImage')
        })

    return images


def lambda_handler(event, context):

    images = list()
    es_url = os.environ.get('ELASTICSEARCH_URL')
    es_index = os.environ.get('ELASTICSEARCH_INDEX')
    if not (es_url and es_index):
        logger.info('ELASTICSEARCH_URL environment variable not found. '
                    'Skipping dump to elasticsearch.')
    else:
        try:
            es = Elasticsearch(es_url)
            es.index(index=es_index, doc_type='alarm', body=event)
            logger.info('Forwarded event to elasticsearch: '
                        '%s@%s', es_url, es_index)
        except Exception as exc:
            logger.info(exc)

    s3path = os.environ.get('S3_PATH')
    if not s3path:
        logger.info('S3_PATH environment variable not found. '
                    'Skipping fetch of graph images.')

    elif '.com/' not in s3path:
        logger.info('S3_PATH should be a path to an online S3 bucket. '
                    'Skipping fetch of graph images.')

    else:

        logger.info('Fetching graph images from cloudwatch...')
        images = get_cloudwatch_graph(event)

        logger.info('Posting images to s3...')
        for image in images:
            if not image:
                continue

            im_name = 'image_%s.png' % (str(time.time()).replace('.', ''))
            im = open(im_name, 'wb')
            im.write(image['data'])
            im.close()

            s3 = boto3.client(
                's3',
                aws_access_key_id=os.environ.get('ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('SECRET_ACCESS_KEY'))

            bucket = s3path.split('.com/')[1].split('/')[0].strip('/')
            path = s3path.split(bucket)[-1]
            path = os.path.join(path, im_name).lstrip('/')

            s3.upload_file(im_name, bucket, path,
                           ExtraArgs={'ACL': 'public-read'})

            image['url'] = os.path.join(s3path, im_name) 
            os.remove(im_name)

    if not os.environ.get('SLACK_WEBHOOK'):
        logger.info('SLACK_WEBHOOK environment variable not found. '
                    'Skipping push to slack.')
    else:    
        report_to_slack(event, images)

    return {
        "statusCode": 200,
        "body": json.dumps({
            'message': 'GTS Lambda executed successfully!'})
    }


if __name__ == "__main__":

    lambda_handler(dict(), dict())
