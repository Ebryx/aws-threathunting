import boto3
from my_argparser import args, write_to_output_file, log_msg, default_vars_dict
from pprint import pprint
import base64


def get_key_val(mDict, key):
	return mDict[key] if key in mDict else ''


def parse_list_secrets(response, region_name):
	'''
	Parses this dict
	{
		'SecretList': [
			{
				'ARN': 'string',
				'Name': 'string',
				'Description': 'string',
				'KmsKeyId': 'string',
				'RotationEnabled': True|False,
				'RotationLambdaARN': 'string',
				'RotationRules': {
					'AutomaticallyAfterDays': 123
				},
				'LastRotatedDate': datetime(2015, 1, 1),
				'LastChangedDate': datetime(2015, 1, 1),
				'LastAccessedDate': datetime(2015, 1, 1),
				'DeletedDate': datetime(2015, 1, 1),
				'Tags': [
					{
						'Key': 'string',
						'Value': 'string'
					},
				],
				'SecretVersionsToStages': {
					'string': [
						'string',
					]
				}
			},
		],
		'NextToken': 'string'
	}

	Returns dictionary -- {'ARN': ['Name', 'KmsKeyId']}
	'''
	log_msg('================\nParsing secret IDs for region: {0}...'.format(region_name))
	secrets_dict = {}
	if response and 'SecretList' in response and len(response['SecretList']) > 0:
		for res in response['SecretList']:
			try:
				pprint('')
				pprint(res)
				ARN = get_key_val(res, 'ARN')
				Name = get_key_val(res, 'Name')
				KmsKeyId = get_key_val(res, 'KmsKeyId')
				secrets_dict[ARN] = [Name, KmsKeyId]
				log_msg('ARN: {0}\nName: {1}\nKmsKeyId: {2}'.format(ARN, Name, KmsKeyId))
			except Exception as e:
				log_msg('Following Exception occurred in parse_list_secrets for region_name {0}'.format(region_name))
				log_msg(e)
				print(e)
	return secrets_dict


def get_all_secret_ids(client, region_name):
	'''
	Takes boot3 client as input.
	Returns dictionary -- {'ARN': ['Name', 'KmsKeyId']}
	'''
	response = None
	secrets_dict = {}
	log_msg('================\nGetting secret IDs for region {0}...'.format(region_name))
	while True:
		if response is None: response = client.list_secrets()
		else: response = client.list_secrets(NextToken=response['NextToken'])
		log_msg('Response:')
		pprint(response)
		secrets_dict.update(parse_list_secrets(response, region_name))
		if 'NextToken' not in response: break
	return secrets_dict


def get_secret_vals(secret_ids, client, region_name):
	'''
	Takes dict -- {'ARN': ['Name', 'KmsKeyId']} as input
	Takes boot3 client as input.
	
	Parses this
	{
		'ARN': 'string',
		'Name': 'string',
		'VersionId': 'string',
		'SecretBinary': b'bytes',
		'SecretString': 'string',
		'VersionStages': [
			'string',
		],
		'CreatedDate': datetime(2015, 1, 1)
	}

	Returns dictionary -- {'ARN': ['SecretBinary', 'SecretString']}
	'''
	secrets_val = {}
	log_msg('================\nGetting secret vals for region {0}...'.format(region_name))
	for secret_id, my_vals in secret_ids.items():
		try:
			response = client.get_secret_value(SecretId=secret_id)
			if response:
				ARN = get_key_val(response, 'ARN')
				secret = None
				if 'SecretString' in response:
					secret = response['SecretString']
				else:
					secret = base64.b64decode(response['SecretBinary'])

				secrets_val[response['ARN']] = secret
				log_msg('ARN: {0}\n==================>>>>Secret: {1}'.format(ARN, secret))
		except Exception as e:
			log_msg('Exception "{0}" occurred in get_secret_vals for secret_id {1}'.format(e, secret_id))
	return secrets_val


def main():
	for region_name in default_vars_dict['aws_secretsmanager_regions']:
		try:
			client = boto3.client('secretsmanager', region_name=region_name)
			secrets_ids = get_all_secret_ids(client, region_name)
			secret_vals = get_secret_vals(secrets_ids, client, region_name)
		except Exception as e:
			log_msg('Exception "{0}" occurred in main of {1} for region {2}'.format(e, str(__file__), region_name))


if __name__ == '__main__':
	main()