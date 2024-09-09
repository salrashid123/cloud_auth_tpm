from google.cloud import storage
from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials

import argparse

parser = argparse.ArgumentParser(description='GCP Auth using TPM')
parser.add_argument("--path", default='/HS/SRK/gcpsign1', required=True)
parser.add_argument("--tcti",default='device:/dev/tpmrm0', required=True)
parser.add_argument("--email",default='tpm-sa@core-eso.iam.gserviceaccount.com', required=True)
parser.add_argument("--project_id",default='core-eso', required=True)
args = parser.parse_args()

pc = GCPCredentials(tcti=args.tcti,
                    path=args.path,
                    profile_dir="./profiles",
                    email=args.email)

storage_client = storage.Client(project=args.project_id, credentials=pc)

buckets = storage_client.list_buckets()
for bkt in buckets:
    print(bkt.name)