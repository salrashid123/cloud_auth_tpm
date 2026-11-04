from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey
from tpm2_pytss.internal.templates import ek_rsa2048
from cloud_auth_tpm.policy.policy import PolicyEval

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from tpm2_pytss.constants import TPM2_PT, TPM2_HR

import backoff

def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest

class TPMHandleException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message

class BaseCredential():

    _parent_ecc_template = TPMT_PUBLIC(
        type=TPM2_ALG.ECC,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
        | TPMA_OBJECT.NODA
        | TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN,
        authPolicy=b"",
        parameters=TPMU_PUBLIC_PARMS(
            eccDetail=TPMS_ECC_PARMS(
                symmetric=TPMT_SYM_DEF_OBJECT(
                    algorithm=TPM2_ALG.AES,
                    keyBits=TPMU_SYM_KEY_BITS(aes=128),
                    mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
                ),
                scheme=TPMT_ECC_SCHEME(scheme=TPM2_ALG.NULL),
                curveID=TPM2_ECC.NIST_P256,
                kdf=TPMT_KDF_SCHEME(scheme=TPM2_ALG.NULL),
            ),
        ),
    )

    DEFAULT_TCTI = "device:/dev/tpmrm0"

    def __init__(
        self,
        tcti,
        keyfile,
        ownerpassword,
        password,
        policy_impl: PolicyEval,
        enc_key_name,
        use_ek_cert,
    ):

        self._tcti = tcti or self.DEFAULT_TCTI
        self._password = password
        self._ownerpassword = ownerpassword
        self._enc_key_name = enc_key_name
        self._use_ek_cert = use_ek_cert

        f = open(keyfile, "r")
        self._kb = f.read()
        f.close()

        self._policy_impl = policy_impl

    @backoff.on_exception(backoff.constant, TPMHandleException, interval=1, max_tries=3)
    def defer_tpm_handles(self):
        # defert_tpm_handles() provides a retry dely when accessing a TPM Handle.
        ###  TPM's have limited number of handles to work with and a handle is usually loaded, used, then released
        ###  this function just adds a delay to prevent concurrent access
        try:
           ectx = ESAPI(tcti=self._tcti)
           ectx.startup(TPM2_SU.CLEAR)
        except Exception as e:
            raise e

        for capability_base in [TPM2_HC.HR_TRANSIENT, TPM2_HC.HR_POLICY_SESSION]: # [0x80000000, 0x02000000]:
            
            more_data = True
            current_handle = capability_base     
            while more_data:
                more_data, cap_data = ectx.get_capability(
                    capability=TPM2_CAP.HANDLES, 
                    prop=current_handle, 
                    property_count=8
                )  
                handles = cap_data.data.handles
                if not handles:
                    break

                if len(handles) > 0:
                     raise TPMHandleException(f"tpm handles in use:  count {len(handles)}")

    def sign(self, data):
        try:
            ectx = ESAPI(tcti=self._tcti)
            ectx.startup(TPM2_SU.CLEAR)

            k = TSSPrivKey.from_pem(self._kb.encode('utf-8'))
            inSensitiveOwner = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

            if self._ownerpassword != None:
                inSensitiveOwner = TPM2B_SENSITIVE_CREATE(
                    TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(self._ownerpassword)))

            if self._use_ek_cert:
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
                    ectx.policy_secret(
                        ESYS_TR.ENDORSEMENT, session, nonce, b"", b"", expiration
                    )
                    ectx.trsess_set_attributes(session, TPMA_SESSION.ENCRYPT | TPMA_SESSION.DECRYPT)
                    return session

                tmpl = ek_rsa2048.template
            
                primary1, ek_pub, _, _, _ = ectx.create_primary(
                    inSensitiveOwner, tmpl, ESYS_TR.ENDORSEMENT)

                ek_name = ek_pub.get_name()
                sess = setup_ek_session(ectx)
                rkeyLoaded = ectx.load(primary1, k.private, k.public,  session1=sess)
                ectx.flush_context(primary1)
            else:
                primary1, _, _, _, _ = ectx.create_primary(
                    inSensitiveOwner,  TPM2B_PUBLIC(publicArea=self._parent_ecc_template))
                rkeyLoaded = ectx.load(primary1, k.private, k.public)
                ectx.flush_context(primary1)
        

            if self._password != '' and self._password != None:
                ectx.tr_set_auth(rkeyLoaded, self._password)

            tmpl = ek_rsa2048.template

            handle, outpub, _, _, _ = ectx.create_primary(
                inSensitiveOwner, tmpl, ESYS_TR.ENDORSEMENT)

            # n = ectx.tr_get_name(handle)
            n = outpub.get_name()
            if self._enc_key_name != "" and self._enc_key_name != None:
                if bytes(n).hex() != self._enc_key_name:
                    raise Exception("session encryption key name mismatch: expected {}, got {}".format(
                        self._enc_key_name, bytes(n).hex()))                

            
            scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
            scheme.details.any.hashAlg = TPM2_ALG.SHA256
            validation = TPMT_TK_HASHCHECK(
                tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
            digest, ticket = ectx.hash(data, TPM2_ALG.SHA256, ESYS_TR.OWNER)

            if self._policy_impl == None:
                hsess = ectx.start_auth_session(
                    tpm_key=handle,
                    bind=ESYS_TR.NONE,
                    session_type=TPM2_SE.HMAC,
                    symmetric=TPMT_SYM_DEF(
                        algorithm=TPM2_ALG.AES,
                        keyBits=TPMU_SYM_KEY_BITS(sym=128),
                        mode=TPMU_SYM_MODE(sym=TPM2_ALG.CFB),
                    ),
                    auth_hash=TPM2_ALG.SHA256,
                )
                ectx.trsess_set_attributes(
                    hsess, (TPMA_SESSION.DECRYPT)
                )
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(
                    digest), scheme, validation, session1=hsess)
            else:
                sess = self._policy_impl.policy_callback(
                    ectx=ectx, handle=handle)
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(digest),
                              scheme, validation, session1=sess)
                
            ectx.flush_context(handle)
            ectx.flush_context(rkeyLoaded)

            return bytes(s.signature.rsassa.sig)
        except Exception as e:
            raise Exception(e)
        finally:

            ectx.close()          
