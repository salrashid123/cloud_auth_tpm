## Google Auth Library for Trusted Platform Module based Service Account Keys 

This is an extension of GPC [google-auth-python](https://github.com/googleapis/google-auth-library-python) specifically intended to use service account credentials which are embedded inside a `Trusted Platform Module (TPM)`.


```python
from google.cloud import storage
from google_auth_tpm.credentials import TPMCredentials

### acquire credential source on the TPM
pc = TPMCredentials(tcti="/dev/tpm0",
                    path="/HS/SRK/sign1",
                    email="jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com")

storage_client = storage.Client(project="$PROJECT_ID", credentials=pc)

buckets = storage_client.list_buckets()
for bkt in buckets:
    print(bkt.name)
```   

on python pypi: [https://pypi.org/project/google-auth-tpm/](https://pypi.org/project/google-auth-tpm/)

>> Note: This code is not supported by google

---

| Option | Description |
|:------------|-------------|
| **`-tcti`** | Path to TPM:  (required; default: `device:/dev/tpmrm0`) |
| **`-path`** | Path to FAPI signing object (required; default: ``) |
| **`-email`** | ServiceAccount email (required; default: ``) |
| **`-scopes`** | Signed Jwt Scopes (optional default: `"https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"`) |
| **`-keyid`** | ServiceAccount keyid (optional; default: ``) |
| **`-expire_in`** | Token expiration in seconds (optional; default: `3600`) |
| **`-profile`** | FAPI Profile name (optional; default: `P_RSA2048SHA256`) |
| **`-system_dir`** | FAPI system_dir (optional; default: `"~/.local/share/tpm2-tss/system/keystore"`) |
| **`-profile_dir`** | FAPI profile_dir (optional; default: `"/etc/tpm2-tss/fapi-profiles"`) |
| **`-user_dir`** | FAPI user_dirs (optional; default: `"~/.local/share/tpm2-tss/user/keystore/"  `) |

---

#### Setup

This library uses the [Feature API](https://tpm2-pytss.readthedocs.io/en/latest/fapi.html) provided through `tpm2_pytss`.

To install that:

```bash
## tpm2-tss > 4.1.0 https://github.com/tpm2-software/tpm2-tss
apt-get install libtss2-dev
python3 -m pip install tpm2-pytss
```

There are several ways you can have a TPM based service account key:

1. create a key on the tpm, use it to create an x509 and upload the certificate 
2. import an the raw private key into the TPM
3. securely transfer a key from on machine to the machine with the TPM and then import

This example will just cover (2) for simplicity.  For more info, see [oauth2/tpm2tokensource](https://github.com/salrashid123/oauth2?tab=readme-ov-file#usage)

For additional examples on using FAPI with python to perform operations, see [salrashid123/tpm2/pytss](https://github.com/salrashid123/tpm2/tree/master/pytss)

Once you install the FAPI, you will need to embed a service account key into the TPM.

Setup a new key and download the json

```bash
export PROJECT_ID=`gcloud config get-value core/project`

gcloud iam service-accounts create jwt-access-svc-account --display-name "Test Service Account"

export SERVICE_ACCOUNT_EMAIL=jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com

gcloud iam service-accounts keys create jwt-access-svc-account.json --iam-account=$SERVICE_ACCOUNT_EMAIL

gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$SERVICE_ACCOUNT_EMAIL --role=roles/storage.admin
```

Extract the `key_id`, `email` and the raw RSA key

```bash
export KEYID=`cat jwt-access-svc-account.json | jq -r '.private_key_id'`

export EMAIL=`cat jwt-access-svc-account.json | jq -r '.client_email'`

cat jwt-access-svc-account.json | jq -r '.private_key' > /tmp/private.pem
```

Now use the `load.py` FAPI commands to embed the key into the TPM and save it at FAPI path of your choice, eg `/HS/SRK/sign1`:

```bash
cd example/
pip3 install -r requirements.txt

# rm -rf ~/.local/share/tpm2-tss   # warning, this'll delete fapi objects you have
python3 load.py --path="/HS/SRK/sign1" --private_key=/tmp/private.pem --tcti=device:/dev/tpmrm0 # --tcti="swtpm:port=2321"


### then run:
python3 main.py --path=/HS/SRK/sign1 --email=$EMAIL --project_id=$PROJECT_ID --tcti=device:/dev/tpmrm0  #--tcti="swtpm:port=2321"
```

### How it works

GCP APIs allows for service account authentication using a [Self-signed JWT with scope](https://google.aip.dev/auth/4111).

What that means is if you take a private key and generate a valid JWT with in the following format, you can just send it to the service as an auth token, that simple.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "abcdef1234567890"
}
{
  "iss": "jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com",
  "sub": "jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com",
  "scope": "https://www.googleapis.com/auth/cloud-platform",
  "iat": 1511900000,
  "exp": 1511903600
}
```

So since we have the RSA key on the TPM, we can use the FAPI to make it "sign" data for the JWT.

#### Local Build

to generate the library from scratch and run local, run 

```bash
python3 setup.py sdist bdist_wheel

cd example
virtualenv env

pip3 install ../
pip3 install -r requirements.txt 
```

#### Software TPM

If you want to test locally, you can use a software TPM `swtpm`:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert 
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear  --log level=5
```

Once its setup, you can export the following environment variables and use this with `tpm2_tools`

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

