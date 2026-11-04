#!/usr/bin/python

import tempfile
from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from cloud_auth_tpm.policy import PCRAuthValuePolicy


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials
from google.cloud import storage

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
  
    # inSensitive = TPM2B_SENSITIVE_CREATE()
    # primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

    # kh = ectx.load(primary1, k.private, k.public)
    # ectx.flush_context(primary1)
    # ectx.flush_context(kh)


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

    ectx.close()