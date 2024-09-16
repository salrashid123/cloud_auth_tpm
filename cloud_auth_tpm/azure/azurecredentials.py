from tpm2_pytss import *

from cloud_auth_tpm.base import BaseCredential

import uuid
import base64
import json
from datetime import datetime, timedelta
import calendar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import base64
import datetime
import requests  # pip install requests
from cryptography import x509  # pip install cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID

from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from azure.identity._internal import validate_tenant_id
from azure.core.credentials import TokenCredential, AccessToken


class AzureCredentials(BaseCredential,TokenCredential):
    def __init__(
        self,
        tcti=None,
        keyfile=None,
        ownerpassword=None,
        password=None,
        policy_impl=None,

        tenant_id=None,
        client_id=None,
        certificate_path=None,
        **kwargs: Any
    ):

        if tenant_id == '' or certificate_path == '' or client_id == '':
            raise Exception("Error : {}".format(
                "tenant_id, certificate_path and client_id must be specified"))

        validate_tenant_id(tenant_id)

        with open(certificate_path, 'r') as f:
            self._cert = x509.load_pem_x509_certificate(f.read().encode())
            self._fingerprint = self._cert.fingerprint(
                hashes.SHA256())  # nosec
            if self._cert.public_key_algorithm_oid != PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5:
                raise Exception("Error : currently only RSAES_PKCS1_v1_5 keys are supported, got {}".format(
                    self._cert.public_key_algorithm_oid))
            if self._cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
                raise Exception("Error : currently only RSA_WITH_SHA256 keys are supported, got {}".format(
                    self._cert.signature_algorithm_oid))

        BaseCredential.__init__(self,tcti=tcti,keyfile=keyfile,ownerpassword=ownerpassword,password=password,policy_impl=policy_impl)
        TokenCredential.__init__(self)

        self._tenant_id = tenant_id
        self._client_id = client_id
        self._certificate_path = certificate_path


    def sha256(self, data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        digest = digest.finalize()
        return digest

    def base64url_decode(self, input):
        return base64.urlsafe_b64decode(input)

    def base64url_encode(self, input):
        stringAsBytes = input.encode('ascii')
        stringAsBase64 = base64.urlsafe_b64encode(
            stringAsBytes).decode('utf-8').replace('=', '')
        return stringAsBase64

    def utcnow(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        now = now.replace(tzinfo=None)
        return now

    def get_token(self, *scopes: str, claims: Optional[str] = None, **kwargs: Any):
        try:
            now = self.utcnow()
            ea = now + timedelta(seconds=10)  # give 10s to do this exchange
            e = ea.replace(tzinfo=None)
            iat = calendar.timegm(now.utctimetuple())
            exp = calendar.timegm(e.utctimetuple())
            header = {
                "alg": "RS256",
                "typ": "JWT",
                "x5t#S256": base64.standard_b64encode(self._fingerprint).decode()
            }
            payload = {
                'aud': "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(self._tenant_id),
                'exp': exp,
                'nbf': iat,
                'id': str(uuid.uuid4()),
                'iss': self._client_id,
                'sub': self._client_id,
            }
            total_params = str(self.base64url_encode(json.dumps(
                header))) + '.' + str(self.base64url_encode(json.dumps(payload)))

            sig = self.sign(data=total_params.encode('utf-8'))

            stringAsBase64 = base64.urlsafe_b64encode(
                sig).decode('utf-8').replace('=', '')
            token = total_params + '.' + stringAsBase64

            headers = {'User-Agent': 'cloud-auth-tpm'}
            payload = {'grant_type': 'client_credentials',
                    'scope': scopes,
                    'client_id': self._client_id,
                    'client_assertion': token,
                    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'}

            session = requests.Session()
            r = session.post("https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(
                self._tenant_id), headers=headers, data=payload)

            if r.status_code != 200:
                raise Exception("Error status code " +
                                str(r.status_code) + "  " + r.text)

            json_data = json.loads(r.text)

            tok = json_data['access_token']
            e = json_data['expires_in']

            now = self.utcnow()
            ea = now + timedelta(seconds=int(e))
            e = ea.replace(tzinfo=None)
            exp = calendar.timegm(e.utctimetuple())

            return AccessToken(tok, exp)
        except Exception as e:
            raise Exception("Error : {}".format(e))