from tpm2_pytss import *

import argparse

parser = argparse.ArgumentParser(description='create RSA key on TPM')
parser.add_argument("--path", default='/HS/SRK/sign1', required=True)
parser.add_argument("--tcti",default='device:/dev/tpmrm0', required=True)
parser.add_argument("--private_key",default='', required=True)

args = parser.parse_args()

FAPIConfig(profile_name='P_RSA2048SHA256',tcti=args.tcti, temp_dirs=False, ek_cert_less='yes',
           system_dir="~/.local/share/tpm2-tss/system/keystore",
           profile_dir="./profiles", ### system profiles are at /usr/local/etc/tpm2-tss/fapi-profiles/ or /etc/tpm2-tss/fapi-profiles/
           user_dir="~/.local/share/tpm2-tss/user/keystore/")


fapi_ctx = FAPI()
try:
    fapi_ctx.provision()
except Exception as e:
    pass

try:
    f = open(args.private_key, "r")
    key_private_pem=f.read()
except Exception as e:
  print(e)
  sys.exit(1)

try:
   fapi_ctx.import_object(path=args.path, import_data=key_private_pem,exists_ok=False)
except Exception as e:
  print(e)
  pass

print('tpm objects:')
l = fapi_ctx.list(search_path="/HS/")
print(l)

#fapi_ctx.delete("/")
fapi_ctx.close()

