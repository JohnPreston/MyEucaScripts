#!/usr/bin/env python

"""

Script to get S3 buckets list (and more ..) using a cross account authentication STS tokens

"""

import boto
import os
import argparse

from boto.sts import STSConnection
from boto import s3
# The calls to AWS STS AssumeRole must be signed using the access key ID and secret
# access key of an IAM user or using existing temporary credentials. (You cannot call
# AssumeRole using the access key for an account.) The credentials can be in
# environment variables or in a configuration file and will be discovered automatically
# by the STSConnection() function. For more information, see the Python SDK
# documentation: http://boto.readthedocs.org/en/latest/boto_config_tut.html

def getStsCredentials(role_name,
                      access_key=None,
                      secret_key=None,
                      debug=False):
    """

    Gets connceted to IAM STS to get the foreign account tokens to perform actions

    """

    if not (access_key and secret_key):
        sts_connection = STSConnection(aws_access_key_id=os.getenv('EC2_ACCESS_KEY'),
                                       aws_secret_access_key=os.getenv('EC2_SECRET_KEY'))
    else:
        return None
    try:
        assumedRoleObject = sts_connection.assume_role(
            role_arn=role_name,
            role_session_name="AssumeRoleSession1",
            external_id='helion-euca-readonly'
            )
    except boto.exception.BotoServerError:
        return None
        
    if debug is True:
        print assumedRoleObject.credentials.access_key
        print assumedRoleObject.credentials.secret_key
        print assumedRoleObject.credentials.session_token
    return {"access_key": assumedRoleObject.credentials.access_key,
            "secret_key": assumedRoleObject.credentials.secret_key,
            "token": assumedRoleObject.credentials.session_token}

def s3_get_all(region,
               sts_creds,
               debug=False):
    """

    Get all buckets information

    """

    try:
        s3_conn = s3.connect_to_region(region,
                                       aws_access_key_id=sts_creds['access_key'],
                                       aws_secret_access_key=sts_creds['secret_key'],
                                       security_token=sts_creds['token'])
        print s3_conn.get_all_buckets()
        
    except:
        print "Smth went wrong"


def getoptions():
    """

    Parser to get the options

    """
    parser = argparse.ArgumentParser(description='Auto-update DHCP config for private only instances')
    parser.add_argument("-a", "--account-serial", metavar="accountserial", type=str, help="the customer account ID you are accessing", required=True)
    parser.add_argument("-r", "--role-name", metavar="rolename", type=str, help="The role name the customer created to get STS credentials", required=True)
    parser.add_argument("-I", "--aws-accesskey", metavar="accesskey", type=str, help="Your AWS Access Key", required=False)
    parser.add_argument("-S", "--aws-secrekey", metavar="secretkey", type=str, help="Your AWS Secret Key", required=False)
    parser.add_argument("--debug", action='store_true', required=False)
    args = parser.parse_args()
    return args

def main():
    """

    Main function(). Will get the STS tokens and use those to get foreign account information

    """

    args = getoptions()
    role_name = "arn:aws:iam::%s:role/%s" % (args.account_serial, args.role_name)
    sts_creds = getStsCredentials(role_name, debug=args.debug)
    if sts_creds:
        s3_get_all('eu-west-1', sts_creds)
    else:
        sys.exit("Could not get the STS account credentials")

if __name__ == '__main__':
    main()
