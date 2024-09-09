## Cloud Auth Library using Trusted Platform Module (TPM)

Python library which supports TPM embedded credentials for various cloud providers.

on python pypi: [https://pypi.org/project/cloud-auth-tpm/](https://pypi.org/project/cloud-auth-tpm/)

> **>>WARNING<<**: This code is not affiliated with or supported by google

---

### Usage

You need to first embed an RSA key into a TPM thats readable by [python-tss](https://github.com/tpm2-software/tpm2-pytss).  See the [Setup](#setup)

##### **GCPCredentials**

```python
from google.cloud import storage
from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials

####  pip3 install cloud_auth_tpm[gcp]
pc = GCPCredentials(tcti="device:/dev/tpmrm0",
                    path="/HS/SRK/gcpsign1",
                    email="jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com")

storage_client = storage.Client(project="$PROJECT_ID", credentials=pc)

buckets = storage_client.list_buckets()
for bkt in buckets:
    print(bkt.name)
```   

##### **AWSCredentials**

```python
import boto3
from cloud_auth_tpm.aws.awscredentials import AWSCredentials

####  pip3 install cloud_auth_tpm[aws]
pc = AWSCredentials(tcti="device:/dev/tpmrm0",
                    path="/HS/SRK/awssign1",
                    profile_dir="./profiles",
                    public_certificate_file="certs/alice-cert.crt",
                    region="us-east-2",
                    duration_seconds=3600,
                    trust_anchor_arn='arn:aws:rolesanywhere:us-east-2:291738886522:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92ac',
                    session_name="foo",
                    role_arn="arn:aws:iam::291738886522:role/rolesanywhere1",
                    profile_arn="arn:aws:rolesanywhere:us-east-2:291738886522:profile/6f4943fb-13d4-4242-89c4-be367595c560")

session = pc.get_session()

s3 = session.resource('s3')
for bucket in s3.buckets.all():
    print(bucket.name)
```

##### **AzureCredentials**

```python
from azure.storage.blob import BlobServiceClient
from cloud_auth_tpm.azure.azurecredentials import AzureCredentials

####  pip3 install cloud_auth_tpm[azure]
pc = AzureCredentials(tcti="device:/dev/tpmrm0",
                    path="/HS/SRK/azuresign1",
                    profile_dir="./profiles",
                    tenant_id="45243fbe-b73f-4f7d-8213-a104a99e428e",
                    client_id="cffeaee2-5617-4784-8a4b-b647efd676e1",
                    certificate_path="certs/azclient.crt")

blob_service_client = BlobServiceClient(
    account_url="https://$STORAGE_ACCOUNT.blob.core.windows.net",
    credential=pc
)
container_client = blob_service_client.get_container_client('mineral-minutia')
blob_list = container_client.list_blobs()
for blob in blob_list:
    print(blob.name)
```

---

### Configuration

| Option | Description |
|:------------|-------------|
| **`tcti`** | Path to TPM:  (required; default: `device:/dev/tpmrm0`) |
| **`path`** | Path to FAPI signing object (required; default: ``) |
| **`profile`** | FAPI Profile name (optional; default: `P_RSA2048SHA256`) |
| **`system_dir`** | FAPI system_dir (optional; default: `"~/.local/share/tpm2-tss/system/keystore"`) |
| **`profile_dir`** | FAPI profile_dir (optional; default: `"/etc/tpm2-tss/fapi-profiles"`) |
| **`user_dir`** | FAPI user_dirs (optional; default: `"~/.local/share/tpm2-tss/user/keystore/"  `) |

##### **GCPCredentials**

| Option | Description |
|:------------|-------------|
| **`email`** | ServiceAccount email (required; default: ``) |
| **`scopes`** | Signed Jwt Scopes (optional default: `"https://www.googleapis.com/auth/cloud-platform"`) |
| **`keyid`** | ServiceAccount keyid (optional; default: ``) |
| **`expire_in`** | Token expiration in seconds (optional; default: `3600`) |

##### **AWSCredentials**

| Option | Description |
|:------------|-------------|
| **`public_certificate_file`** | Path to public x509 (required; default: ``) |
| **`region`** | AWS Region (optional default: ``) |
| **`duration_seconds`** | Duration in seconds for the token lifetime (optional; default: `3600`) |
| **`trust_anchor_arn`** | RolesAnywhere Trust anchor ARN (required; default: ``) |
| **`role_arn`** | RolesAnywhere RoleArn (required; default: ``) |
| **`profile_arn`** | RolesAnywhere Profile Arn (Required; default: ``) |
| **`session_name`** | AWS Session Name (optional; default: ``) |

##### **AzureCredentials**

| Option | Description |
|:------------|-------------|
| **`tenant_id`** | Azure TentantID (required; default: ``) |
| **`client_id`** | Azure Application (client) ID (required; default: ``) |
| **`certificate_path`** | x509 certificate to authenticate with (required; default ``) |

---

### Setup

This library uses the [Feature API](https://tpm2-pytss.readthedocs.io/en/latest/fapi.html) provided through `tpm2_pytss`.

You need to first install [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) `version>=4.1.0` (see [issue#596](https://github.com/tpm2-software/tpm2-pytss/issues/596))

```bash
## tpm2-tss > 4.1.0 https://github.com/tpm2-software/tpm2-tss
apt-get install libtss2-dev
python3 -m pip install tpm2-pytss
```

#### Using RSA Keys on TPM

You can initialize a TPM based RSA key and optional certificate in several ways:

1. create a key on the tpm
2. import an the raw private key into the TPM
3. securely transfer a key from on machine to the machine with the TPM and then import

This example will just cover (2) for simplicity which for the FAPI, is done using the [example/load.py](example/load.py) utility.  

For more info, see [oauth2/tpm2tokensource](https://github.com/salrashid123/oauth2?tab=readme-ov-file#usage)

For additional examples on using FAPI with python to perform operations, see [salrashid123/tpm2/pytss](https://github.com/salrashid123/tpm2/tree/master/pytss)


#### Setup - GCP

This is an extension of GCP [google-auth-python](https://github.com/googleapis/google-auth-library-python) specifically intended to use service account credentials which are embedded inside a `Trusted Platform Module (TPM)`.

Setup a new key and download the json

```bash
export PROJECT_ID=`gcloud config get-value core/project`
export SERVICE_ACCOUNT_EMAIL=jwt-access-svc-account@$PROJECT_ID.iam.gserviceaccount.com

gcloud iam service-accounts create jwt-access-svc-account --display-name "Test Service Account"
gcloud iam service-accounts keys create jwt-access-svc-account.json --iam-account=$SERVICE_ACCOUNT_EMAIL
gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$SERVICE_ACCOUNT_EMAIL --role=roles/storage.admin
```

Extract the `key_id`, `email` and the raw RSA key

```bash
export KEYID=`cat jwt-access-svc-account.json | jq -r '.private_key_id'`
export SERVICE_ACCOUNT_EMAIL=`cat jwt-access-svc-account.json | jq -r '.client_email'`

cat jwt-access-svc-account.json | jq -r '.private_key' > /tmp/private.pem
```

Now use the `load.py` FAPI commands to embed the key into the TPM and save it at FAPI path of your choice, eg `/HS/SRK/sign1`:

```bash
cd example/
# rm -rf ~/.local/share/tpm2-tss   # warning, this will clear any FAPI objects

python3 load.py --path="/HS/SRK/gcpsign1" \
   --private_key=/tmp/private.pem \
  --tcti="swtpm:port=2321" # --tcti=device:/dev/tpmrm0

### then run:
pip3 install -r requirements-gcp.txt

python3 main_gcp.py --path=/HS/SRK/gcpsign1 \
   --email=$SERVICE_ACCOUNT_EMAIL --project_id=$PROJECT_ID  \
   --tcti="swtpm:port=2321" # --tcti=device:/dev/tpmrm0
```

##### How it works - GCP

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

#### Setup - AWS

[AWS Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) allows for client authentication based on digital signature from trusted private keys.

The trusted client RSA or EC key is embedded within a TPM and that is used to sign the RolesAnywhere header values.

In the example in this repo, we will use a *EXAMPLE* CA and key.  If you follow this setup, you are using a the rsa key and CA found in this repo....so  *please* remember to use test resources and promptly delete/disable this.

The specific certificate CA and private key is the same as described in the sample here:

* [AWA RolesAnywhere Signer](https://github.com/salrashid123/aws_rolesanywhere_signer)

When you setup RolesAnywhere, note down the ARN for the `TrustAnchorArn`, `ProfileArn` and `RoleArn` as well as the `region`.  Ideally, the role has `AmazonS3ReadOnlyAccess` to list buckets.

We'll use  `example/load.py` FAPI commands to embed the key into the TPM and save it at FAPI path of your choice, eg `/HS/SRK/awssign1`:

```bash
cd example/
# rm -rf ~/.local/share/tpm2-tss   # warning, this will clear any FAPI objects

python3 load.py --path="/HS/SRK/awssign1" \
  --private_key=certs/alice-cert.key \
  --tcti="swtpm:port=2321" # --tcti=device:/dev/tpmrm0 
```

Then attempt to use the credentials and specify the specific ARN values

```bash
export CERTIFICATE="certs/alice-cert.crt"
export REGION="us-east-2"
export TRUST_ANCHOR_ARN="arn:aws:rolesanywhere:us-east-2:291738886522:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92ac"
export ROLE_ARN="arn:aws:iam::291738886522:role/rolesanywhere1"
export PROFILE_ARN="arn:aws:rolesanywhere:us-east-2:291738886522:profile/6f4943fb-13d4-4242-89c4-be367595c560"

pip3 install -r requirements-aws.txt

python3 main_aws.py --public_certificate_file=$CERTIFICATE \
   --region=$REGION  --trust_anchor_arn=$TRUST_ANCHOR_ARN \
     --role_arn=$ROLE_ARN \
          --profile_arn=$PROFILE_ARN \
            --path="/HS/SRK/awssign1" \
             --tcti="swtpm:port=2321" # --tcti=device:/dev/tpmrm0
```

Currently ONLY RSASSA  keys are supported (its easy enough to support others, TODO)

An alternative to using this library is invoking a process to acquire credentials from any SDK.  See: [AWS Process Credentials for Trusted Platform Module (TPM)](https://github.com/salrashid123/aws-tpm-process-credential).

TODO: once FAPI supports hmac, i'll try to add on HMAC auth too  ref: [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac) and specifically [AWS v4 signed request using Trusted Platform Module](https://gist.github.com/salrashid123/bca7a24e1d59567adb89fef093d8564d)

#### Setup - Azure

Azure authentication uses an the basic [Microsoft identity platform application authentication certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) where the variation here is that the client rsa key is on the TPM

The following example assumes you have set this up.  You can find an example/test setup here:

* [KMS, TPM and HSM based Azure Certificate Credentials](https://github.com/salrashid123/azsigner)

We'll use  `example/load.py` FAPI commands to embed the key into the TPM and save it at FAPI path of your choice, eg `/HS/SRK/azuresign1`:

```bash
cd example/
# rm -rf ~/.local/share/tpm2-tss   # warning, this will clear any FAPI objects

python3 load.py --path="/HS/SRK/azuresign1" \
   --private_key=certs/azclient.key \
      --tcti="swtpm:port=2321" # --tcti=device:/dev/tpmrm0 
```

Then configure env vars (the )

```bash
## this is just the public cert and key pem in one file
export CERTIFICATE_PATH_COMBINED_DER="certs/azclient-cert-key.pem" 
## this is just the public cert
export CERTIFICATE_PATH="certs/azclient.crt" 
export CLIENT_ID="cffeaee2-5617-4784-8a4b-b647efd676e1"
export TENANT_ID="45243fbe-b73f-4f7d-8213-a104a99e428e"

## test that you have the cert based auth working
az login --service-principal -u $CLIENT_ID -p $CERTIFICATE_PATH_COMBINED_DER --tenant=$TENANT_ID
az account get-access-token   --scope="api://$CLIENT_ID/.default"

## if the principal has access to a storage container, test that
export STORAGE_ACCOUNT=your-storage-account
export CONTAINER=your-container
export AZURE_TOKEN=$(az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv)

curl -s --oauth2-bearer "$AZURE_TOKEN"  -H 'x-ms-version: 2017-11-09'  \
     "https://$STORAGE_ACCOUNT.blob.core.windows.net/$CONTAINER?restype=container&comp=list" | xmllint -  --format

## now you're ready to test with the client using the embedded TPM key

pip3 install -r requirements-azure.txt

python3 main_azure.py --certificate_path=$CERTIFICATE_PATH \
      --client_id=$CLIENT_ID  --tenant_id=$TENANT_ID \
       --path="/HS/SRK/azuresign1" \
       --tcti="swtpm:port=2321"  # --tcti=device:/dev/tpmrm0
```

Currently ONLY RSASSA  keys are supported (its easy enough to support others, TODO)

#### Local Build

to generate the library from scratch and run local, run 

```bash
python3 setup.py sdist bdist_wheel

cd example
virtualenv env
source env/bin/activate

pip3 install ../
## depending on the variant provider
# pip3 install -r requirements-gcp.txt 
# pip3 install -r requirements-aws.txt 
# pip3 install -r requirements-azure.txt 


### to deploy/upload
# virtualenv env 
# source env/bin/activate
# python3 -m pip install --upgrade build
# python3 -m pip install --upgrade twine
# python3 -m build
# python3 -m twine upload --repository testpypi dist/*
# python3 -m twine upload  dist/*
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
