from tpm2_pytss import *
from tpm2_pytss.utils import *
from tpm2_pytss.internal import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from tpm2_pytss.tsskey import TSSPrivKey


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
  
def loadHMAC(ectx, key=None):
    try:
        inSensitive = TPM2B_SENSITIVE_CREATE()
        primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

        scheme = TPMT_KEYEDHASH_SCHEME(scheme=TPM2_ALG.HMAC)
        scheme.details.hmac.hashAlg = TPM2_ALG.SHA256
        objectAttributes=TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT
        
        sensitive, pu = TPM2B_SENSITIVE.keyedhash_from_secret(secret=key.encode("utf-8"),scheme=scheme,objectAttributes=objectAttributes)

        symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
        symdef.mode.sym = TPM2_ALG.CFB
        symdef.keyBits.sym = 128
        enckey, duplicate, outsymseed = wrap(
                parent.publicArea, pu, sensitive, b"", symdef
        )
        priv = ectx.import_(primary1, enckey, pu, duplicate, outsymseed, symdef)

        childHandle = ectx.load(primary1, priv, pu)

        k1= TSSPrivKey(priv,pu,empty_auth=True,parent=TPM2_RH.OWNER)
        ectx.flush_context(primary1)
        ectx.flush_context(childHandle)

    except Exception as e:
        raise Exception("error occured creating HMAC Key {}".format(e))
    return k1


def loadRSA(ectx, private_key):
    try:
        inSensitive = TPM2B_SENSITIVE_CREATE()
        primary1, parent, _, _, _ = ectx.create_primary(inSensitive,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))

        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        modulus_n = public_numbers.n
        n_bytes = modulus_n.to_bytes((modulus_n.bit_length() + 7) // 8, byteorder='big')

        public  = TPM2B_PUBLIC(
            publicArea=TPMT_PUBLIC(
                type=TPM2_ALG.RSA,
                nameAlg=TPM2_ALG.SHA256,
                objectAttributes=TPMA_OBJECT.USERWITHAUTH 
                        | TPMA_OBJECT.SIGN_ENCRYPT,
                parameters=TPMU_PUBLIC_PARMS(
                    rsaDetail=TPMS_RSA_PARMS(
                        exponent=0, #public_numbers.e,
                        keyBits=2048,
                        symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
                        scheme=TPMT_RSA_SCHEME(
                            scheme=TPM2_ALG.RSASSA,
                            details=TPMU_ASYM_SCHEME(
                                TPMS_SCHEME_HASH(
                                hashAlg=TPM2_ALG.SHA256,
                            )
                            ),
                        ),                    
                    ),
                ),
                unique=TPMU_PUBLIC_ID(
                    rsa=n_bytes
                ),
            )
        )

        pem_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        sensitive = TPM2B_SENSITIVE.from_pem(data=pem_private_key)
        
        symdef = TPMT_SYM_DEF_OBJECT(algorithm=TPM2_ALG.AES)
        symdef.mode.sym = TPM2_ALG.CFB
        symdef.keyBits.sym = 128

        enckey, duplicate, outsymseed = wrap(
                parent.publicArea, public, sensitive, b"", symdef
        )
        priv = ectx.import_(primary1, enckey, public, duplicate, outsymseed, symdef)
        childHandle = ectx.load(primary1, priv, public)
        k = TSSPrivKey(private=priv,public=public, empty_auth=True,parent=primary1)
        ectx.flush_context(primary1)
        ectx.flush_context(childHandle)

    except Exception as e:
        raise Exception("error occured creating RSA Key {}".format(e))
    return k