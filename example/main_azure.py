from azure.storage.blob import BlobServiceClient
from cloud_auth_tpm.azure.azurecredentials import AzureCredentials
from cloud_auth_tpm.policy import PCRPolicy

import argparse

parser = argparse.ArgumentParser(description='Azure auth using TPM')
parser.add_argument("--tcti", default='device:/dev/tpmrm0', required=True)
parser.add_argument("--keyfile", default='', required=True)
parser.add_argument("--ownerpassword", default='')
parser.add_argument("--password", default='')
parser.add_argument("--pcr", default='')

parser.add_argument("--certificate_path",
                    default="certs/azclient.crt", required=True)
parser.add_argument(
    "--tenant_id", default="45243fbe-b73f-4f7d-8213-a104a99e428e", required=True)
parser.add_argument(
    "--client_id", default="cffeaee2-5617-4784-8a4b-b647efd676e1", required=False)
parser.add_argument("--storageaccount",
                    default="mineralminutia", required=False)
parser.add_argument("--container", default="mineral-minutia", required=False)

args = parser.parse_args()


if args.pcr == '':
    pc = AzureCredentials(
        tcti=args.tcti,
        keyfile=args.keyfile,
        ownerpassword=args.ownerpassword,
        password=args.password,
        policy_impl=None,

        tenant_id=args.tenant_id,
        client_id=args.client_id,
        certificate_path=args.certificate_path)
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
    pc = AzureCredentials(
        tcti=args.tcti,
        keyfile=args.keyfile,
        ownerpassword=args.ownerpassword,
        password=args.password,
        policy_impl=PCRPolicy(policy=pol),

        tenant_id=args.tenant_id,
        client_id=args.client_id,
        certificate_path=args.certificate_path)
    

blob_service_client = BlobServiceClient(
    account_url="https://{}.blob.core.windows.net".format(args.storageaccount),
    credential=pc
)
container_client = blob_service_client.get_container_client(args.container)

blob_list = container_client.list_blobs()
for blob in blob_list:
    print(blob.name)
