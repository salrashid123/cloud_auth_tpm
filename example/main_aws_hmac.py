import boto3
from cloud_auth_tpm.aws.awshmaccredentials import AWSHMACCredentials
from cloud_auth_tpm.policy import PCRPolicy

import argparse

parser = argparse.ArgumentParser(description='AWS auth using TPM')
parser.add_argument("--tcti", default='device:/dev/tpmrm0', required=True)
parser.add_argument("--keyfile", default='', required=True)
parser.add_argument("--ownerpassword", default='')
parser.add_argument("--password", default='')
parser.add_argument("--pcr", default='')

parser.add_argument("--aws_access_key_id", default='', required=True)
parser.add_argument("--region", default="us-east-1", required=True)

parser.add_argument("--get_session_token", default=False)

parser.add_argument(
    "--assume_role_arn", default="arn:aws:iam::291738886548:role/gcpsts", required=False)
parser.add_argument(
    "--role_session_name", default="foo", required=False)

args = parser.parse_args()

if args.pcr == '':

    pc = AWSHMACCredentials(
        tcti=args.tcti,
        keyfile=args.keyfile,
        ownerpassword=args.ownerpassword,
        password=args.password,
        policy_impl=None,

        access_key=args.aws_access_key_id,
        region=args.region,
        duration_seconds=3600,
        role_session_name=args.role_session_name,
        assume_role_arn=args.assume_role_arn,

        get_session_token=args.get_session_token
)

else:
    pol = {
        "description": "Policy PCR {} TPM2_ALG_SHA256".format(args.pcr),
        "policy": [
            {
                "type": "POLICYPCR",
                "pcrs": [
                    {
                        "pcr": args.pcr,
                        "hashAlg": "TPM2_ALG_SHA256",
                        "digest": "0000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            }
        ]
    }
    pc = AWSHMACCredentials(
        tcti=args.tcti,
        keyfile=args.keyfile,
        ownerpassword=args.ownerpassword,
        password=args.password,
        policy_impl=PCRPolicy(policy=pol),

        access_key=args.aws_access_key_id,
        region=args.region,
        duration_seconds=3600,
        role_session_name=args.role_session_name,
        assume_role_arn=args.assume_role_arn,

        get_session_token=args.get_session_token)


session = pc.get_session()

s3 = session.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)
