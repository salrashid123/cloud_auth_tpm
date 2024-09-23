from tpm2_pytss import *
from google.cloud import storage
from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials
from cloud_auth_tpm.policy import PCRPolicy, PCRAuthValuePolicy

import argparse

parser = argparse.ArgumentParser(description='GCP Auth using TPM')
parser.add_argument("--tcti", default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='')
parser.add_argument("--ownerpassword", default='')
parser.add_argument("--password", default='')
parser.add_argument("--pcr", default='')
parser.add_argument("--enc_key_name", default='')

parser.add_argument(
    "--email", default='tpm-sa@core-eso.iam.gserviceaccount.com')
parser.add_argument("--project_id", default='core-eso')

args = parser.parse_args()

policy_impl = None

# if your pcr value bound to is:
# $ tpm2_pcrread sha256:23
#    sha256:
#     23: 0x0000000000000000000000000000000000000000000000000000000000000000

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

if args.pcr != '' and args.password != '':
    policy_impl = PCRAuthValuePolicy(policy=pol)
elif args.pcr != '':
    policy_impl = PCRPolicy(policy=pol)

pc = GCPCredentials(tcti=args.tcti,
                    keyfile=args.keyfile,
                    ownerpassword=args.ownerpassword,
                    password=args.password,
                    policy_impl=policy_impl,
                    enc_key_name=args.enc_key_name,
                    email=args.email)

storage_client = storage.Client(project=args.project_id, credentials=pc)

buckets = storage_client.list_buckets()
for bkt in buckets:
    print(bkt.name)
