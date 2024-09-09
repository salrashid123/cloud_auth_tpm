import boto3
from cloud_auth_tpm.aws.awscredentials import AWSCredentials

import argparse

parser = argparse.ArgumentParser(description='AWS auth using TPM')
parser.add_argument("--path", default='/HS/SRK/awssign1', required=True)
parser.add_argument("--tcti",default='device:/dev/tpmrm0', required=True)

parser.add_argument("--public_certificate_file",default="certs/alice-cert.crt", required=True)
parser.add_argument("--region",default="us-east-2", required=True)
parser.add_argument("--trust_anchor_arn",default='arn:aws:rolesanywhere:us-east-2:291738886522:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92ac', required=False)
parser.add_argument("--role_arn",default="arn:aws:iam::291738886522:role/rolesanywhere1", required=False)
parser.add_argument("--profile_arn",default="arn:aws:rolesanywhere:us-east-2:291738886522:profile/6f4943fb-13d4-4242-89c4-be367595c560", required=False)

args = parser.parse_args()

pc = AWSCredentials(tcti=args.tcti,
                    path=args.path,
                    profile_dir="./profiles",
                    public_certificate_file=args.public_certificate_file,
                    region=args.region,
                    duration_seconds=1000,
                    trust_anchor_arn=args.trust_anchor_arn,session_name="foo",role_arn=args.role_arn,profile_arn=args.profile_arn)

session = pc.get_session()

s3 = session.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)


