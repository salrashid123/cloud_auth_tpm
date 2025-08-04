from tpm2_pytss import *
from google.cloud import storage
from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials
from cloud_auth_tpm.policy import PCRPolicy, PCRAuthValuePolicy, PolicyORAndDuplicateSelectPolicy

from tpm2_pytss import *
from tpm2_pytss.internal.templates import _ek
from tpm2_pytss.tsskey import TSSPrivKey

import argparse

### you will first need to use tpmcopy to transfer a key from TPM-A to TPM-B:
##### https://github.com/salrashid123/tpmcopy/tree/main?tab=readme-ov-file#setup-software-tpm
##### then reference the key on TPM-B to access GCP (eg export --password=bar --tcti="swtpm:port=2341")


parser = argparse.ArgumentParser(description='GCP Auth using TPM')
parser.add_argument("--tcti", default='device:/dev/tpmrm0')
parser.add_argument("--keyfile", default='')
parser.add_argument("--ownerpassword", default='')
parser.add_argument("--password", default='')
parser.add_argument("--ek_name", default='')
parser.add_argument("--enc_key_name", default='')

parser.add_argument(
    "--email", default='tpm-sa@redacted.iam.gserviceaccount.com')
parser.add_argument("--project_id", default='')

args = parser.parse_args()


if args.ek_name == '':
    ectx = ESAPI(tcti=args.tcti)
    ectx.startup(TPM2_SU.CLEAR)
    def setup_ek_session(ectx):
        sym = TPMT_SYM_DEF(
            algorithm=TPM2_ALG.XOR,
            keyBits=TPMU_SYM_KEY_BITS(exclusiveOr=TPM2_ALG.SHA256),
            mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
        )
        session = ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric=sym,
            auth_hash=TPM2_ALG.SHA256,
        )
        nonce = ectx.trsess_get_nonce_tpm(session)
        expiration = -(10 * 365 * 24 * 60 * 60)
        ectx.policy_secret(ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
        )
        ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
        return session

    nv, tmpl = _ek.EK_RSA2048

    inSensitive = TPM2B_SENSITIVE_CREATE(
            TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(args.ownerpassword))) 
    ek_handle, ek_pub, _, _, _ = ectx.create_primary(
        inSensitive, tmpl, ESYS_TR.ENDORSEMENT)

    args.ek_name = ek_pub.get_name()
    ectx.flush_context(ek_handle)
    ectx.close()    
    
print(args.ek_name)

policy_impl = None

pol={
    "name": "MyPolicyOR",
    "description":"Policy OR",
    "policy": [
        {
         "type": "or",
            "branches": [ 
                 {
                    "name": "authvalue",
                    "description":"Policy AuthValue",
                    "policy": [
                        {
                            "type": "authValue",
                        }
                    ]    
                },
                {
                    "name": "duplicationSelect",
                    "description":"Policy DuplicateSelect",
                    "policy": [
                        {
                            "type": "duplicationSelect",
                            "newParentName": "{}".format(args.ek_name),
                        }
                    ]    
                },                
            ],
        },
    ],
}

policy_impl = PolicyORAndDuplicateSelectPolicy(policy=pol)

pc = GCPCredentials(tcti=args.tcti,
                    keyfile=args.keyfile,
                    ownerpassword=args.ownerpassword,
                    password=args.password,
                    policy_impl=policy_impl,
                    enc_key_name=args.enc_key_name,
                    use_ek_cert=False,
                    
                    email=args.email)

storage_client = storage.Client(project=args.project_id, credentials=pc)

buckets = storage_client.list_buckets()
for bkt in buckets:
    print(bkt.name)
