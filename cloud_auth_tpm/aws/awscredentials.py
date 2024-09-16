from tpm2_pytss import *

from cloud_auth_tpm.base import BaseCredential

import base64
import json
from datetime import datetime


import base64
import datetime
import hashlib
import requests  # pip install requests
from cryptography import x509  # pip install cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID

from boto3 import Session
from botocore.credentials import RefreshableCredentials, CredentialProvider
from botocore.session import get_session


class AWSCredentials(BaseCredential, CredentialProvider):

    METHOD = 'tpm-credential'

    def __init__(
        self,
        tcti=None,
        keyfile=None,
        ownerpassword=None,
        password=None,
        policy_impl=None,

        public_certificate_file=None,
        region=None,
        duration_seconds=3600,
        trust_anchor_arn=None,
        profile_arn=None,
        role_arn=None,
        session_name=None,



        **kwargs: Any
    ):
        BaseCredential.__init__(self, tcti=tcti, keyfile=keyfile,
                                ownerpassword=ownerpassword, password=password, policy_impl=policy_impl)
        CredentialProvider.__init__(self)

        self._public_certificate_file = public_certificate_file
        self._region = region
        self._duration_seconds = duration_seconds
        self._profile_arn = profile_arn
        self._role_arn = role_arn
        self._session_name = session_name
        self._trust_anchor_arn = trust_anchor_arn
        self._long_running_session = None
        self._endpoint = 'https://rolesanywhere.{}.amazonaws.com'.format(
            self._region)

        if self._public_certificate_file == '' or self._region == '' or self._trust_anchor_arn == '' or self._profile_arn == '' or self._role_arn == '':
            raise Exception("Error : {}".format(
                "public_certificate_file, region trust_anchor_arn, _role_arn and  profile_arn must be specified"))

        # Load public certificate
        with open(self._public_certificate_file, 'r') as f:
            self._cert = x509.load_pem_x509_certificate(f.read().encode())

        # ref: https://dev.to/li_chastina/auto-refresh-aws-tokens-using-iam-role-and-boto3-2cjf
        session = get_session()
        session_credentials = RefreshableCredentials.create_from_metadata(metadata=self._refresh(),
                                                                          refresh_using=self._refresh,
                                                                          method=self.METHOD)
        session._credentials = session_credentials
        session.set_config_variable('region', self._region)
        self._long_running_session = Session(botocore_session=session)

    def _refresh(self):
        try:
            # source:  https://nerdydrunk.info/aws:roles_anywhere
            method = 'POST'
            service = 'rolesanywhere'
            host = 'rolesanywhere.{}.amazonaws.com'.format(self._region)
            content_type = 'application/json'

            amz_x509 = str(base64.b64encode(self._cert.public_bytes(
                encoding=serialization.Encoding.DER)), 'utf-8')
            serial_number_dec = self._cert.serial_number
            request_parameters = '{'
            request_parameters += '"durationSeconds": {},'.format(
                self._duration_seconds)
            request_parameters += '"profileArn": "{}",'.format(
                self._profile_arn)
            request_parameters += '"roleArn": "{}",'.format(self._role_arn)
            request_parameters += '"sessionName": "{}",'.format(
                self._session_name)
            request_parameters += '"trustAnchorArn": "{}"'.format(
                self._trust_anchor_arn)
            request_parameters += '}'

            t = datetime.datetime.now(datetime.UTC)
            amz_date = t.strftime('%Y%m%dT%H%M%SZ')
            # Date w/o time, used in credential scope
            date_stamp = t.strftime('%Y%m%d')
            canonical_uri = '/sessions'
            canonical_querystring = ''
            canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + \
                '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-x509:' + amz_x509 + '\n'
            signed_headers = 'content-type;host;x-amz-date;x-amz-x509'

            payload_hash = hashlib.sha256(
                request_parameters.encode('utf-8')).hexdigest()

            canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + \
                '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
            if self._cert.public_key_algorithm_oid == PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5:
                algorithm = 'AWS4-X509-RSA-SHA256'
                if self._cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
                    raise Exception("Error : currently only RSA_WITH_SHA256 keys are supported, got {}".format(
                        self._cert.signature_algorithm_oid))
            elif self._cert.public_key_algorithm_oid == PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
                algorithm = 'AWS4-X509-ECDSA-SHA256'
                raise Exception("Error : currently only RSA keys are supported, got ECDSA {}".format(
                    self._cert.signature_algorithm_oid))
            else:
                raise Exception("unknown algorithm: {}".format(
                    self._cert.public_key_algorithm_oid))

            credential_scope = date_stamp + '/' + self._region + \
                '/' + service + '/' + 'aws4_request'
            string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + \
                '\n' + \
                hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

            sig = self.sign(data=string_to_sign.encode('utf-8'))

            signature_hex = sig.hex()
            authorization_header = algorithm + ' ' + 'Credential=' + \
                str(serial_number_dec) + '/' + credential_scope + ', ' + \
                'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature_hex

            headers = {'Content-Type': content_type,
                       'X-Amz-Date': amz_date,
                       'X-Amz-X509': amz_x509,
                       'Authorization': authorization_header}

            r = requests.post(self._endpoint + canonical_uri,
                              data=request_parameters, headers=headers)

            if r.status_code != 201:
                raise Exception("Error status code " +
                                str(r.status_code) + "  " + r.text)

            json_data = json.loads(r.text)

            if len(json_data['credentialSet']) == 0:
                raise Exception("invalid response, no credentialSet ")

            c = json_data['credentialSet'][0]['credentials']

            datetime_object = datetime.datetime.strptime(
                c['expiration'], '%Y-%m-%dT%H:%M:%SZ')

            metadata = {
                'access_key': c['accessKeyId'],
                'secret_key': c['secretAccessKey'],
                'token': c['sessionToken'],
                'expiry_time': datetime_object.replace(tzinfo=datetime.UTC).isoformat()
            }
            return metadata
        except Exception as e:
            raise Exception("Error : {}".format(e))

    def get_session(self):
        return self._long_running_session
