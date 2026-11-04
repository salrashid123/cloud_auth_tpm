#!/usr/bin/python

import tempfile
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from cloud_auth_tpm.policy import PCRAuthValuePolicy


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cloud_auth_tpm.aws.awscredentials import AWSCredentials
from cloud_auth_tpm.aws.awshmaccredentials import AWSHMACCredentials
import boto3


from .utils import loadHMAC, loadRSA, _parent_ecc_template

import os
import unittest

swtpm = "swtpm:port=2321"

 
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
  
    # inSensitive = TPM2B_SENSITIVE_CREATE()
    # primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    # kh = ectx.load(primary1, k.private, k.public)
    # ectx.flush_context(primary1)
    # ectx.flush_context(kh)

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
  
    # inSensitive = TPM2B_SENSITIVE_CREATE()
    # primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    # kh = ectx.load(primary1, k.private, k.public)
    # ectx.flush_context(primary1)
    # ectx.flush_context(kh)

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".pem") as tmp_file:
        tmp_file.write(k.to_pem().decode("utf-8"))
        tmp_file_path = tmp_file.name


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



if __name__ == "__main__":
    unittest.main()    