from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey

from cloud_auth_tpm.policy.policy import PolicyEval

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    digest = digest.finalize()
    return digest


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
    ):

        self._tcti = tcti or self.DEFAULT_TCTI
        self._password = password
        self._ownerpassword = ownerpassword

        f = open(keyfile, "r")
        self._kb = f.read()
        f.close()

        self._policy_impl = policy_impl

    def sign(self, data):

        try:
            ectx = ESAPI(tcti=self._tcti)
            ectx.startup(TPM2_SU.CLEAR)

            k = TSSPrivKey.from_pem(self._kb.encode('utf-8'))
            inSensitiveOwner = TPM2B_SENSITIVE_CREATE(TPMS_SENSITIVE_CREATE())

            if self._ownerpassword != None:
                inSensitiveOwner = TPM2B_SENSITIVE_CREATE(
                    TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(self._ownerpassword)))

            primary1, _, _, _, _ = ectx.create_primary(
                inSensitiveOwner,  TPM2B_PUBLIC(publicArea=self._parent_ecc_template))

            rkeyLoaded = ectx.load(primary1, k.private, k.public)
            ectx.flush_context(primary1)

            digest = sha256(data)
            scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.RSASSA)
            scheme.details.any.hashAlg = TPM2_ALG.SHA256
            validation = TPMT_TK_HASHCHECK(
                tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.OWNER)
            digest, ticket = ectx.hash(data, TPM2_ALG.SHA256, ESYS_TR.OWNER)

            if self._password != None:
                ectx.tr_set_auth(rkeyLoaded, self._password)

            if self._policy_impl == None:
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(
                    digest), scheme, validation)
            else:
                sess = self._policy_impl.policy_callback(ectx=ectx)
                s = ectx.sign(rkeyLoaded, TPM2B_DIGEST(digest),
                              scheme, validation, session1=sess)
                ectx.flush_context(sess)
            ectx.flush_context(rkeyLoaded)
            ectx.close()

            return bytes(s.signature.rsassa.sig)
        except Exception as e:
            raise Exception(e)
