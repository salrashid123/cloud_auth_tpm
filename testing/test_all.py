#!/usr/bin/python

import tempfile
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from cloud_auth_tpm.policy import PCRAuthValuePolicy


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials
from google.cloud import storage


from cloud_auth_tpm.aws.awscredentials import AWSCredentials
from cloud_auth_tpm.aws.awshmaccredentials import AWSHMACCredentials
import boto3

from cloud_auth_tpm.azure.azurecredentials import AzureCredentials
from azure.storage.blob import BlobServiceClient

from .utils import loadHMAC, loadRSA, _parent_ecc_template

import os
import unittest

swtpm = "swtpm:port=2321"

class TestGCP(unittest.TestCase):

  def testGCSKey(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    SA_EMAIL = os.getenv('CICD_SA_EMAIL')
    SA_PEM = os.getenv('CICD_SA_PEM')
    SA_PROJECT = os.getenv('CICD_SA_PROJECT')
    SA_CICD_BUCKET = os.getenv('CICD_BUCKET')

    private_key = serialization.load_pem_private_key(
          SA_PEM.encode('utf-8'),
          password=None,
          backend=default_backend()
    )
    k = loadRSA(ectx,private_key)
  
    inSensitive = TPM2B_SENSITIVE_CREATE()
    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    kh = ectx.load(primary1, k.private, k.public)
    ectx.flush_context(primary1)

    # scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
    # scheme.details.any.hashAlg = TPM2_ALG.SHA256
    # validation = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
    # digest, ticket = ectx.hash(b"fff", TPM2_ALG.SHA256, ESYS_TR.OWNER)
    # s = ectx.sign(kh, TPM2B_DIGEST(digest), scheme, validation)
    # print("signature:")
    # print(s.signature.rsassa.sig)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(k.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    

    pc = GCPCredentials(tcti=swtpm,
                        keyfile=tmp_file_path,
                        ownerpassword=None,
                        password=None,
                        policy_impl=None,
                        enc_key_name=None,
                        email=SA_EMAIL)

    storage_client = storage.Client(project=SA_PROJECT, credentials=pc)

    blobs = storage_client.list_blobs(SA_CICD_BUCKET)
    for blob in blobs:
      self.assertEqual(blob.name, "foo.txt")

    ectx.flush_context(kh)
    ectx.close()

 
class TestAWS(unittest.TestCase):
  def testS3RolesAnywhere(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    CICD_AWS_CERT = os.getenv('CICD_AWS_CERT')
    CICD_AWS_PEM = os.getenv('CICD_AWS_PEM')
    CICD_AWS_REGION = os.getenv('CICD_AWS_REGION')
    CICD_AWS_TRUST_ANCHOR_ARN = os.getenv('CICD_AWS_TRUST_ANCHOR_ARN')
    CICD_AWS_ROLE_ARN = os.getenv('CICD_AWS_ROLE_ARN')
    CICD_AWS_PROFILE_ARN = os.getenv('CICD_AWS_PROFILE_ARN')

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
      tmp_file.write(CICD_AWS_CERT)
      tmp_file_cert = tmp_file.name    


    private_key = serialization.load_pem_private_key(
          CICD_AWS_PEM.encode('utf-8'),
          password=None,
          backend=default_backend()
    )
    k = loadRSA(ectx,private_key)
  
    inSensitive = TPM2B_SENSITIVE_CREATE()
    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    kh = ectx.load(primary1, k.private, k.public)
    ectx.flush_context(primary1)
    ectx.flush_context(kh)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(k.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name    

    
    pc = AWSCredentials(tcti=swtpm,
                        keyfile=tmp_file_path,
                        ownerpassword=None,
                        password=None,
                        policy_impl=None,
                        enc_key_name=None,
                        use_ek_cert=False,

                        public_certificate_file=tmp_file_cert,
                        region=CICD_AWS_REGION,
                        duration_seconds=1000,
                        trust_anchor_arn=CICD_AWS_TRUST_ANCHOR_ARN,
                        session_name="foo",
                        role_arn=CICD_AWS_ROLE_ARN,
                        profile_arn=CICD_AWS_PROFILE_ARN)


    session = pc.get_session()

    s3 = session.resource('s3')
    ectx.close()

    lenbuckets=(len(list(s3.buckets.all())))
    self.assertGreaterEqual(1,lenbuckets)

  def testS3HMAC(self):

    ectx = ESAPI(tcti=swtpm)
    ectx.startup(TPM2_SU.CLEAR)

    CICD_AWS_ACCESS_KEY = os.getenv('CICD_AWS_ACCESS_KEY')
    CICD_AWS_ACCESS_SECRET = os.getenv('CICD_AWS_ACCESS_SECRET')
    CICD_AWS_HMAC_REGION = os.getenv('CICD_AWS_HMAC_REGION')
    CICD_AWS_ROLE_ARN = os.getenv('CICD_AWS_ROLE_ARN')

    k = loadHMAC(ectx,'AWS4{}'.format(CICD_AWS_ACCESS_SECRET))
  
    inSensitive = TPM2B_SENSITIVE_CREATE()
    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(k.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name

    kh = ectx.load(primary1, k.private, k.public)
    ectx.flush_context(primary1)
    ectx.flush_context(kh)

    rolesessionName = "mysession"

    pc = AWSHMACCredentials(tcti=swtpm,
                        keyfile=tmp_file_path,
                        ownerpassword=None,
                        password=None,
                        policy_impl=None,
                        enc_key_name=None,
                        use_ek_cert=False,

                        access_key=CICD_AWS_ACCESS_KEY,
                        region=CICD_AWS_HMAC_REGION,
                        duration_seconds=3600,
                        role_session_name=rolesessionName,
                        assume_role_arn=CICD_AWS_ROLE_ARN,

                        get_session_token=False)



    session = pc.get_session()

    s3 = session.resource('s3')
    ectx.close()

    lenbuckets=(len(list(s3.buckets.all())))
    self.assertGreaterEqual(1,lenbuckets)


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

    inSensitive = TPM2B_SENSITIVE_CREATE()
    primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    kh = ectx.load(primary1, k.private, k.public)
    ectx.flush_context(primary1)
    ectx.flush_context(kh)

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