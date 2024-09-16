from tpm2_pytss import *

from cloud_auth_tpm.base import BaseCredential
from tpm2_pytss.tsskey import TSSPrivKey

import json
from datetime import datetime
import hmac

import datetime
import hashlib
import requests  # pip install requests

from boto3 import Session
from botocore.credentials import RefreshableCredentials, CredentialProvider
from botocore.session import get_session


class AWSHMACCredentials(CredentialProvider):

    METHOD = 'tpm-hmac-credential'

    def __init__(
        self,
        tcti=None,
        keyfile=None,
        ownerpassword=None,
        password=None,
        policy_impl=None,

        region=None,
        duration_seconds=3600,

        access_key=None,
        assume_role_arn=None,
        role_session_name=None,
        tags=None,

        get_session_token=False,
        **kwargs: Any
    ):
        CredentialProvider.__init__(self)

        self._tcti = tcti
        self._keyfile = keyfile

        self._ownerpassword = ownerpassword
        self._password = password
        self._policy_impl = policy_impl

        self._region = region
        self._duration_seconds = duration_seconds

        self._access_key = access_key
        self._assume_role_arn = assume_role_arn
        self._role_session_name = role_session_name
        self._tags = tags

        self._get_session_token = get_session_token

        if self._assume_role_arn == '' and self._get_session_token == False:
            raise Exception("Error : {}".format(
                "if get_session_token is not set, _assume_role_arn values must must be specified"))

        self._long_running_session = None

        if self._tcti == '' or self._region == '' or self._keyfile == '' or self._region == '' or self._access_key == '':
            raise Exception("Error : {}".format(
                "tcti, region _keyfile, _role_arn access_key and  profile_arn must be specified"))

        # Load public keyfile
        with open(keyfile, 'r') as f:
            self._keyfile = f.read()
            f.close()

        # ref: https://dev.to/li_chastina/auto-refresh-aws-tokens-using-iam-role-and-boto3-2cjf
        session = get_session()
        session_credentials = RefreshableCredentials.create_from_metadata(metadata=self._refresh(),
                                                                          refresh_using=self._refresh,
                                                                          method=self.METHOD)
        session._credentials = session_credentials
        session.set_config_variable('region', self._region)
        self._long_running_session = Session(botocore_session=session)

    def _sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _getSignatureKey(self, key, dateStamp, regionName, serviceName):

        # instead of the first hmac operation using the AWS Secret, use the TPM based key
        # kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
        ectx = ESAPI(tcti=self._tcti)
        ectx.startup(TPM2_SU.CLEAR)

        k = TSSPrivKey.from_pem(self._keyfile.encode('utf-8'))
        inSensitiveOwner = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

        if self._ownerpassword != None:
            inSensitiveOwner = TPM2B_SENSITIVE_CREATE(
                TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(self._ownerpassword)))

        primary1, _, _, _, _ = ectx.create_primary(
            inSensitiveOwner,  TPM2B_PUBLIC(publicArea=BaseCredential._parent_ecc_template))

        hkeyLoaded = ectx.load(primary1, k.private, k.public)
        ectx.flush_context(primary1)

        if self._password != None:
            ectx.tr_set_auth(hkeyLoaded, self._password)

        if self._policy_impl == None:
            thmac = ectx.hmac(hkeyLoaded, dateStamp, TPM2_ALG.SHA256)
        else:
            sess = self._policy_impl.policy_callback(ectx=ectx)
            thmac = ectx.hmac(hkeyLoaded, dateStamp,
                              TPM2_ALG.SHA256, session1=sess)
            ectx.flush_context(sess)

        ectx.flush_context(hkeyLoaded)
        kDate = thmac.__bytes__()
        ectx.close()

        kRegion = self._sign(kDate, regionName)
        kService = self._sign(kRegion, serviceName)
        kSigning = self._sign(kService, "aws4_request")
        return kSigning

    def _refresh(self):
        try:
            # Request parameters
            method = 'POST'
            service = 'sts'
            host = "sts.amazonaws.com"

            endpoint = '/'

            # Create a datetime object for signing
            t = datetime.datetime.utcnow()
            amzdate = t.strftime('%Y%m%dT%H%M%SZ')
            datestamp = t.strftime('%Y%m%d')

            # Create the canonical request
            canonical_uri = endpoint

            canonical_querystring = ''
            canonical_headers = 'content-type:application/x-www-form-urlencoded' + \
                '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'

            signed_headers = 'content-type;host;x-amz-date'

            # https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
            # payload = 'Action=GetCallerIdentity&Version=2011-06-15'
            if self._get_session_token:
                payload = 'Action=GetSessionToken&DurationSeconds={}&Version=2011-06-15'.format(
                    self._duration_seconds)
            else:
                payload = 'Action=AssumeRole&DurationSeconds={}&RoleSessionName={}&RoleArn={}&Version=2011-06-15'.format(
                    self._duration_seconds, self._region, self._assume_role_arn)

            payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
            canonical_request = (method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n'
                                 + canonical_headers + '\n' + signed_headers + '\n' + payload_hash)

            # Create the string to sign
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = datestamp + '/' + self._region + \
                '/' + service + '/' + 'aws4_request'
            string_to_sign = (algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' +
                              hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())

            # Sign the string
            signing_key = self._getSignatureKey(
                self._access_key, datestamp, self._region, service)
            signature = hmac.new(signing_key, (string_to_sign).encode(
                'utf-8'), hashlib.sha256).hexdigest()

            # Add signing information to the request
            authorization_header = (algorithm + ' ' + 'Credential=' + self._access_key + '/' + credential_scope + ', ' +
                                    'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature)
            # Make the request
            headers = {'content-type': 'application/x-www-form-urlencoded',
                       'host': host,
                       'x-amz-date': amzdate,
                       'Accept': 'application/json',
                       'Authorization': authorization_header}
            request_url = 'https://' + host + canonical_uri

            r = requests.post(request_url, headers=headers,
                              data=payload, allow_redirects=False, timeout=5)

            if r.status_code != 200:
                raise Exception("Error status code " +
                                str(r.status_code) + "  " + r.text)

            json_data = json.loads(r.text)

            if self._get_session_token:
                if len(json_data['GetSessionTokenResponse']) == 0:
                    raise Exception(
                        "invalid response, no GetSessionTokenResponse ")
                c = json_data['GetSessionTokenResponse']['GetSessionTokenResult']['Credentials']
            else:
                if len(json_data['AssumeRoleResponse']) == 0:
                    raise Exception("invalid response, no AssumeRoleResponse ")
                c = json_data['AssumeRoleResponse']['AssumeRoleResult']['Credentials']

            datetime_object = datetime.datetime.utcfromtimestamp(
                int(c['Expiration']))

            metadata = {
                'access_key': c['AccessKeyId'],
                'secret_key': c['SecretAccessKey'],
                'token': c['SessionToken'],
                'expiry_time': datetime_object.replace(tzinfo=datetime.UTC).isoformat()
            }

            return metadata
        except Exception as e:
            raise Exception("Error : {}".format(e))

    def get_session(self):
        return self._long_running_session
