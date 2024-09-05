from tpm2_pytss import *

import base64
import json
from datetime import datetime, timedelta, timezone
import calendar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from google.auth import credentials, _helpers
from google.auth import exceptions

_TIMEOUT = 2


class TPMCredentials(credentials.CredentialsWithQuotaProject):

    def __init__(
        self,
        tcti="device:/dev/tpmrm0",
        path=None,
        email=None,
        scopes="https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email",
        key_id=None,
        expire_in=3600,
        profile = 'P_RSA2048SHA256',
        system_dir="~/.local/share/tpm2-tss/system/keystore",
        profile_dir="/etc/tpm2-tss/fapi-profiles",
        user_dir = "~/.local/share/tpm2-tss/user/keystore/"        
    ):

        super(TPMCredentials, self).__init__()
        self._tcti = tcti
        self._path = path
        self._email = email
        self._scopes = scopes
        self._key_id = key_id
        self._profile = profile
        self._expire_in = expire_in
        self._system_dir = system_dir
        self._profile_dir = profile_dir
        self._user_dir = user_dir

        if self._path == '' or self._email == '':
            raise exceptions.DefaultCredentialsError("Error : {}".format("email and path must be specified"))
        
        self.token = None
        self.expiry = None

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
        digest = self.sha256(total_params.encode())
        sig, pub,cert = self._fapi_ctx.sign(path=self._path, digest=digest, padding="rsa_ssa")
        stringAsBase64 = base64.urlsafe_b64encode(sig).decode('utf-8').replace('=','')
        token = total_params + '.' + stringAsBase64
        return token

    def refresh(self, request):
        self._update_token(request)

    def _update_token(self, request):

        try:

            FAPIConfig(profile_name=self._profile,tcti=self._tcti, temp_dirs=False, ek_cert_less='yes',
                    system_dir=self._system_dir,
                    profile_dir=self._profile_dir,
                    user_dir=self._user_dir)

            self._fapi_ctx = FAPI()

            now = _helpers.utcnow()
            ea = now + timedelta(seconds=self._expire_in)
            e = ea.replace(tzinfo=None)
            iat = calendar.timegm(now.utctimetuple())
            exp = calendar.timegm(e.utctimetuple())

            self.token = self.jwt_token(iat,exp, self._key_id,self._email, self._scopes)
            self.expiry =  e
            self._fapi_ctx.close()
        except Exception as e:
            raise exceptions.RefreshError("Error : {}".format(e))

    def with_quota_project(self, quota_project_id):
        return self.__class__(
            tcti="/dev/tpmrm0",
            path=None,
            email=None,
            scopes="https://www.googleapis.com/auth/cloud-platform",
            key_id=None,
            expire_in=3600,
            quota_project_id=quota_project_id,
        )

