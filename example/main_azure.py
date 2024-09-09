from azure.storage.blob import BlobServiceClient
from cloud_auth_tpm.azure.azurecredentials import AzureCredentials

import argparse

parser = argparse.ArgumentParser(description='Azure auth using TPM')
parser.add_argument("--path", default='/HS/SRK/azuresign1', required=True)
parser.add_argument("--tcti",default='device:/dev/tpmrm0', required=True)

parser.add_argument("--certificate_path",default="certs/azclient.crt", required=True)
parser.add_argument("--tenant_id",default="45243fbe-b73f-4f7d-8213-a104a99e428e", required=True)
parser.add_argument("--client_id",default="cffeaee2-5617-4784-8a4b-b647efd676e1", required=False)

args = parser.parse_args()

pc = AzureCredentials(tcti=args.tcti,
                    path=args.path,
                    profile_dir="./profiles",
                    tenant_id=args.tenant_id,
                    client_id=args.client_id,
                    certificate_path=args.certificate_path)

blob_service_client = BlobServiceClient(
    account_url="https://mineralminutia.blob.core.windows.net",
    credential=pc
)
container_client = blob_service_client.get_container_client('mineral-minutia')

blob_list = container_client.list_blobs()
for blob in blob_list:
    print(blob.name)

