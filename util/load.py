from tpm2_pytss import *
from tpm2_pytss.tsskey import TSSPrivKey

import argparse
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# pip install git+https://github.com/tpm2-software/tpm2-pytss.git

parser = argparse.ArgumentParser(
    description='convert public/private key to h2 keyfile')

parser.add_argument("--tcti", default="swtpm:port=2321", required=False)
parser.add_argument("--public", default='', required=True)
parser.add_argument("--private", default='', required=True)
parser.add_argument("--ownerPassword", default='')
parser.add_argument("--keyPassword", default='')
parser.add_argument("--out", default='/tmp/key.pem', required=True)

args = parser.parse_args()



# read the tpm2_tools generated public/private
f = open(args.public, "rb")
pubb = f.read()
f.close()

f = open(args.private, "rb")
privb = f.read()
f.close()

tpm2b_pub, _ = TPM2B_PUBLIC.unmarshal(pubb)
tpm2b_priv, _ = TPM2B_PRIVATE.unmarshal(privb)

## this step just makes sure you can load the key correctly; this is optional
if args.tcti != '':
    ectx = ESAPI(tcti=args.tcti)
    ectx.startup(TPM2_SU.CLEAR)

    # the H2 template
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

    inSensitiveOwner = TPM2B_SENSITIVE_CREATE(
        TPMS_SENSITIVE_CREATE(userAuth=TPM2B_AUTH(args.ownerPassword))
    )
    primary1, _, _, _, _ = ectx.create_primary(
        inSensitiveOwner,  TPM2B_PUBLIC(publicArea=_parent_ecc_template))
    inSensitive = TPM2B_SENSITIVE_CREATE()
    rkey = ectx.load(primary1, tpm2b_priv, tpm2b_pub)
    ectx.flush_context(primary1)
    ectx.flush_context(rkey)

# # *************************

# write the keys to a PEM file
empty_auth = True
if args.keyPassword != '':
    empty_auth = False
k1 = TSSPrivKey(tpm2b_priv, tpm2b_pub,
                empty_auth=empty_auth, parent=TPM2_RH.OWNER)
p1 = k1.to_pem()
f = open(args.out, "w")
f.write(p1.decode())
f.close()

print(p1.decode())
