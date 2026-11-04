#!/usr/bin/python

import tempfile
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from cloud_auth_tpm.policy import PCRAuthValuePolicy


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


from cloud_auth_tpm.azure.azurecredentials import AzureCredentials
from azure.storage.blob import BlobServiceClient

from .utils import loadHMAC, loadRSA, _parent_ecc_template

import os
import unittest

swtpm = "swtpm:port=2321"


class TestAzure(unittest.TestCase):
  def testCertificateAuth(self):
    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    CICD_AZURE_CLIENT_PEM = os.getenv('CICD_AZURE_CLIENT_PEM')
    CICD_AZURE_CERT = os.getenv('CICD_AZURE_CERT')    
    CICD_AZURE_TENANT_ID = os.getenv('CICD_AZURE_TENANT_ID')
    CICD_AZURE_CLIENT_ID = os.getenv('CICD_AZURE_CLIENT_ID')
    CICD_AZURE_STORAGEACCOUNT = os.getenv('CICD_AZURE_STORAGEACCOUNT')
    CICD_AZURE_CONTAINER = os.getenv('CICD_AZURE_CONTAINER')

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
      tmp_file.write(CICD_AZURE_CERT)
      tmp_file_cert = tmp_file.name    


    private_key = serialization.load_pem_private_key(
          CICD_AZURE_CLIENT_PEM.encode('utf-8'),
          password=None,
          backend=default_backend()
    )
    k = loadRSA(ectx,private_key)

    # inSensitive = TPM2B_SENSITIVE_CREATE()
    # primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    # kh = ectx.load(primary1, k.private, k.public)
    # ectx.flush_context(primary1)
    # ectx.flush_context(kh)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(k.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    

    pc = AzureCredentials(
        tcti=swtpm,
        keyfile=tmp_file_path,
        ownerpassword=None,
        password=None,
        policy_impl=None,
        enc_key_name=None,
        use_ek_cert=False,

        tenant_id=CICD_AZURE_TENANT_ID,
        client_id=CICD_AZURE_CLIENT_ID,
        certificate_path=tmp_file_cert)

    blob_service_client = BlobServiceClient(
        account_url="https://{}.blob.core.windows.net".format(CICD_AZURE_STORAGEACCOUNT),
        credential=pc
    )
    container_client = blob_service_client.get_container_client(CICD_AZURE_CONTAINER)

    blob_list = container_client.list_blobs()
    ectx.close()    
    lenbuckets=(len(list(blob_list)))
    self.assertGreaterEqual(1,lenbuckets)


if __name__ == "__main__":
    unittest.main()    