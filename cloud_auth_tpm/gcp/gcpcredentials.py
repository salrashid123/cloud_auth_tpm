
from tpm2_pytss import *

from cloud_auth_tpm.base import BaseCredential
from google.auth.credentials import Credentials

import base64
import json
from datetime import timedelta
import calendar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from google.auth import credentials, _helpers
from google.auth import exceptions


class GCPCredentials(credentials.Credentials, credentials.Signing):    

    def __init__(
        self,
        tcti=None,
        keyfile=None,
        ownerpassword=None,
        password=None,
        policy_impl=None,
        enc_key_name=None,
        use_ek_cert=False,        

        email=None,
        scopes="https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email",
        key_id=None,
        expire_in=3600,
    ):
        super().__init__()

        self._signer = BaseCredential(tcti=tcti,keyfile=keyfile,ownerpassword=ownerpassword,password=password,policy_impl=policy_impl,enc_key_name=enc_key_name,use_ek_cert=use_ek_cert)

        self._email = email
        self._scopes = scopes
        self._key_id = key_id
        self._expire_in = expire_in

        if self._email == '' or self._email == None:
            raise exceptions.DefaultCredentialsError("Error : {}".format("email and path must be specified"))
        
        self.token = None
        self.expiry = None    

    def key_id(self):
        self._key_id

    def sign_bytes(self, message):
        return self._signer.sign(data=message)

    def signer(self):
        return self

    def signer_email(self):
        return self._email

    def sha256(self,data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        digest = digest.finalize()
        return digest

    def base64url_decode(self,input):
        return base64.urlsafe_b64decode(input)

    def base64url_encode(self,input):
        stringAsBytes = input.encode('ascii')
        stringAsBase64 = base64.urlsafe_b64encode(stringAsBytes).decode('utf-8').replace('=','')
        return stringAsBase64 

    def jwt_token(self,iat, exp, key_id, email, scopes):
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": key_id,
        }
        payload = {
            'iat': iat,
            'exp': exp,
            'sub': email,
            'iss': email,
            'scope': scopes,
        }
        total_params = str(self.base64url_encode(json.dumps(header))) + '.' + str(self.base64url_encode(json.dumps(payload)))
        sig = self._signer.sign(data=total_params.encode())
        stringAsBase64 = base64.urlsafe_b64encode(sig).decode('utf-8').replace('=','')
        token = total_params + '.' + stringAsBase64
        return token
    
    def refresh(self, request):
        self._signer.defer_tpm_handles()
        try:
            now = _helpers.utcnow()
            ea = now + timedelta(seconds=self._expire_in)
            iat = calendar.timegm(now.utctimetuple())
            exp = calendar.timegm(ea.utctimetuple())
            self.token = self.jwt_token(iat,exp, self._key_id,self._email, self._scopes)
            self.expiry =  ea          
        except Exception as e:
            raise Exception("Error : {}".format(e))
