import argparse
import time
from datetime import datetime


args = ''
default_vars_dict = {
    'log_file': '{0}.log'.format(str(__file__)),
    'out_file': '{0}-out-{1}.txt'.format(str(__file__), int(time.time())),
    # 'aws_secretsmanager_regions': ["us-east-2", "us-east-1", "us-west-1", "us-west-2", "ap-south-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "sa-east-1"]
    'aws_secretsmanager_regions': ['eu-west-1']
}


def setup_argparse():
    global args
    argparse_setup_completed_gracefully = False
    parser = argparse.ArgumentParser(
        description='''This script does this and that''',
        epilog="""All's well that ends well""",
        usage="""python3 {0}.py""".format(str(__file__)))
    parser.add_argument('--out_file', '-o', '-O', '-OUTPUT', 
        required=False,
        help='path/to/name/of/output/file',
        default=default_vars_dict['out_file']
    )
    parser.add_argument('--log_file', '-lf',
        required=False,
        help='path/to/name/of/log_file/file',
        default=default_vars_dict['log_file']
    )

    args = parser.parse_args()
    default_vars_dict['out_file'] = args.out_file
    argparse_setup_completed_gracefully = True
    return argparse_setup_completed_gracefully


def log_msg(msg, add_enter=True, also_write_to_output_file=False):
    with open(args.log_file, 'a') as o:
        msg = str(msg)
        msg = '{0} ======== {1}'.format(datetime.today(), msg)
        o.write(msg + '\n')
        if also_write_to_output_file:
            write_to_output_file(msg)
        if add_enter:
            msg += '\n'
        print(msg)


def prepare_log_file(log_file):
    with open(log_file, 'w') as o: pass


def prepare_output_file(out_file):
    with open(out_file, 'w') as o: pass


def write_to_output_file(msg, out_file=default_vars_dict['out_file']):
    with open(out_file, 'a') as o:
        o.write(msg)


def main():
    setup_argparse()
    prepare_log_file(args.log_file)
    prepare_output_file(args.out_file)
    log_msg('Argparse Setup completed')


if __name__ == '__main__':
    main()
else:
    main()
