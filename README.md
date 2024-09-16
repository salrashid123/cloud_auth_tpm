## Cloud Auth Library using Trusted Platform Module (TPM)

Python library which supports TPM embedded credentials for various cloud providers.

on python pypi: [https://pypi.org/project/cloud-auth-tpm/](https://pypi.org/project/cloud-auth-tpm/)

> **>>WARNING<<**: This code is not affiliated with or supported by google

---

### Usage

You need to first embed an RSA key into a TPM thats readable by [python-tss](https://github.com/tpm2-software/tpm2-pytss) or openssl and accessed using [PEM formatted TPM Keys](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html).  To do that, see the [Using RSA Keys on TPM](#using-rsa-keys-on-tpm) section for options.

##### **GCPCredentials**

```python
from google.cloud import storage
from cloud_auth_tpm.gcp.gcpcredentials import GCPCredentials

####  pip3 install cloud_auth_tpm[gcp]
pc = GCPCredentials(
  tcti="device:/dev/tpmrm0",
  keyfile='/path/to/key.pem',   # TPM KEY: -----BEGIN TSS2 PRIVATE KEY-----
  ownerpassword=None,
  password=None,
  policy_impl=None,
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
pc = AWSCredentials(
  tcti="device:/dev/tpmrm0",
  keyfile='/path/to/key.pem',   # TPM KEY: -----BEGIN TSS2 PRIVATE KEY-----
  ownerpassword=None,
  password=None,
  policy_impl=None,

  public_certificate_file="certs/alice-cert.crt",
  region="us-east-2",
  duration_seconds=1000,
  trust_anchor_arn='arn:aws:rolesanywhere:us-east-2:291738886522:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92ac',
  session_name="foo", 
  role_arn="arn:aws:iam::291738886522:role/rolesanywhere1",
  profile_arn="arn:aws:rolesanywhere:us-east-2:291738886522:profile/6f4943fb-13d4-4242-89c4-be367595c560")

session = pc.get_session()

s3 = session.resource('s3')
for bucket in s3.buckets.all():
    print(bucket.name)
```

##### **AWSHMACCredentials**

```python
import boto3
from cloud_auth_tpm.aws.awshmaccredentials import AWSHMACCredentials

####  pip3 install cloud_auth_tpm[aws]
pc = AWSHMACCredentials(
  tcti="device:/dev/tpmrm0",
  keyfile='/path/to/key.pem',   # TPM KEY: -----BEGIN TSS2 PRIVATE KEY-----
  ownerpassword=None,
  password=None,
  policy_impl=None,

  access_key="AWS_ACCESS_KEY_ID",
  region="us-east-2",
  duration_seconds=1000,
  role_session_name="foo",
  assume_role_arn="arn:aws:iam::291738886522:role/gcpsts")

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
pc = AzureCredentials(
  tcti="device:/dev/tpmrm0",
  keyfile='/path/to/key.pem',   # TPM KEY: -----BEGIN TSS2 PRIVATE KEY-----
  ownerpassword=None,
  password=None,
  policy_impl=None,

  tenant_id="45243fbe-b73f-4f7d-8213-a104a99e428e",
  client_id="cffeaee2-5617-4784-8a4b-b647efd676e1",
  certificate_path="certs/azclient.crt")

blob_service_client = BlobServiceClient(
    account_url="https://$STORAGE_ACCOUNT.blob.core.windows.net",
    credential=pc
)
container_client = blob_service_client.get_container_client('container_name')
blob_list = container_client.list_blobs()
for blob in blob_list:
    print(blob.name)
```

---

### Configuration

| Option | Description |
|:------------|-------------|
| **`tcti`** | Path to TPM:  (required; default: `device:/dev/tpmrm0`) |
| **`keyfile`** | Path to TPM PEM keyfile:  (required; default: ``) |
| **`ownerpassword`** | Password for the OWNER hierarchy used by H2 template:  (optional; default: ``) |
| **`password`** | Password for the Key (userAuth):  (optional; default: ``) |
| **`policy_impl`** | Concrete implementation class for Policy:  (optional; default: ``) |

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
| **`aws_access_key_id`** | AWS_ACCESS_KEY_ID if using HMAC based credentials (optional; default: ``) |

##### **AWSHMACCredentials**

| Option | Description |
|:------------|-------------|
| **`region`** | AWS Region (optional default: ``) |
| **`aws_access_key_id`** | AWS_ACCESS_KEY_ID if using HMAC based credentials (required; default: ``) |
| **`duration_seconds`** | Duration in seconds for the token lifetime (optional; default: `3600`) |
| **`get_session_token`** | If using GetSessionToken (optional; default: `False`) |
| **`assume_role_arn`** | AssumeRole ARN (required if AssumeRole set; default: ``) |
| **`role_session_name`** | RoleSessionName if AssumeRole set (optional; default: ``) |

##### **AzureCredentials**

| Option | Description |
|:------------|-------------|
| **`tenant_id`** | Azure TentantID (required; default: ``) |
| **`client_id`** | Azure Application (client) ID (required; default: ``) |
| **`certificate_path`** | x509 certificate to authenticate with (required; default ``) |

---

### Setup

This library uses the [Enhanced Systems API (ESAPI)](https://tpm2-pytss.readthedocs.io/en/latest/esys.html) provided through `tpm2_pytss`.   If you are interested in a branch which uses the `Feature API (FAPI)`, see the [fapi](https://github.com/salrashid123/cloud_auth_tpm/tree/fapi) branch in this repo.

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

This example will just cover (2) for simplicity using [tpm2_tools](https://github.com/tpm2-software/tpm2-tools) and the ESAP utility functions in [util/](util).  

For more info, see [oauth2/tpm2tokensource](https://github.com/salrashid123/oauth2?tab=readme-ov-file#usage)

For additional examples on using ESAPI with python to perform operations, see [salrashid123/tpm2/pytss](https://github.com/salrashid123/tpm2/tree/master/pytss)

First step is to acquire the private RSA keys for whichever provider you're interested in

- `GCP`

  Uses [Service Account Self-signed JWT](https://google.aip.dev/auth/4111 ) with Scopes.
  
  Extract the service account json's private key and embed into the TPM.

- `AWS`

  Uses [IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) which involves using a local RSA key to authenticate

  This repo also supports `AWS HMAC Credentials` which you can embed into a TPM.

- `Azure`

   Uses [Azure Certificate Credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials)


Once you have the raw RSA private key in in regular PEM format, you can use [tpm2_tools](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_import.1.md#import-an-rsa-key) to load the key into the TPM.  Each provider has its own way to create the raw RSA key and associate it with a cloud credential.  See instructions below for each provider.

Note, you don't have to use `tpm2_tools`: alternatives is to use [ESAPI](https://github.com/salrashid123/tpm2/tree/master/pytss) directly or [go-tpm](https://github.com/salrashid123/tpm2/tree/master/rsa_import)

For this implementation, each key's parent is defined using the standard [H2 TPM template for ECC](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html).  This allows use of the PEM formatted Keys compatible with `openssl`.

The example in this repo converts the TPM public/private blobs to PEM format using python.   As mentioned, you can also directly use [tpm2genkey](https://github.com/salrashid123/tpm2genkey?tab=readme-ov-file#convert-tpm2b_public-tpm2b_private-with-tpmhtpermanent-h2-template----pem) or for simple keys [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md)

##### Password Auth

If you want to provide a passphrase to use the TPM based key, you can setup userAuth based access.  To skip password based auth, omit the `-p $KEY_PASSWORD` option during tpm key generation and `--keyPassword=` option while converting to set no auth on the keyfile 

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321"  # for real tpm use device:/dev/tpmrm0
export KEY_PASSWORD=passwd

cd /tmp/
### create H2 template
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat


# import the key, note we're setting the password.  
## Each provider has a different way to get this rsa private key; see examples below
tpm2_import -C primary.ctx  -G rsa2048:rsassa:null \
   -g sha256 -i rsakey.pem -u rsa.pub -r rsa.prv -p $KEY_PASSWORD

tpm2_load -C primary.ctx -u  rsa.pub -r  rsa.prv -c  rsa.ctx 

tpm2_readpublic -c  rsa.ctx  -o  rsapub.pem -f PEM -Q 
cat  rsapub.pem

## convert pub/priv blobs to PEM (remember to specify the full path --public --private and --out)
cd util/
python3 load.py --public=rsa.pub \
   --private=rsa.prv --out=rsatpm.pem \
   --keyPassword=$KEY_PASSWORD # --tcti=$TPM2TOOLS_TCTI
```

##### PCR Policy

To create a key with a PCR policy (i.,e a policy which enforces the key can only be used if certain PCR values exist)

```bash
export TPM2TOOLS_TCTI="swtpm:port=2321" # for real tpm use device:/dev/tpmrm0
export PCR=23
export HASH=sha256
export PCRBANK=$HASH:$PCR

cd /tmp/
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256 \
    -c primary.ctx \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

## set a pcr policy trial session and import the key
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l "$PCRBANK"  -L policy.dat
tpm2_flushcontext session.dat

tpm2_import -C primary.ctx  -G rsa2048:rsassa:null \
   -g sha256 -i rsakey.pem -u rsa.pub -r rsa.prv -L policy.dat

tpm2_load -C primary.ctx -u rsa.pub -r rsa.prv -c .ctx 

tpm2_readpublic -c rsa.ctx  -o rsapub.pem -f PEM -Q 
cat rsapub.pem

## convert pub/priv to PEM
cd util/
python3 load.py  --public=rsa.pub \
 --private=rsa.prv --out=rsatpm.pem # --tcti=$TPM2TOOLS_TCTI
```

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

Extract the `key_id`, `email` and the raw RSA key.

```bash
export KEYID=`cat jwt-access-svc-account.json | jq -r '.private_key_id'`
export SERVICE_ACCOUNT_EMAIL=`cat jwt-access-svc-account.json | jq -r '.client_email'`

cat jwt-access-svc-account.json | jq -r '.private_key' > /tmp/rsakey.pem
```

At this point, you need to embed the _raw_ RSA key at `/tmp/rsakey.pem` into the TPM.   See the section above in using the `util/load.py` script.

Once the key is embedded into the TPM, you can discard the raw key since the TPM based version in PEM format is now at `rsakey.pem` (for example) which you can reference it directly for access:

```bash
cd example/
pip3 install -r requirements-gcp.txt

### Password
python3 main_gcp.py --keyfile=rsatpm.pem \
  --email=$SERVICE_ACCOUNT_EMAIL --project_id=$PROJECT_ID \
   --password=$KEY_PASSWORD --tcti=$TPM2TOOLS_TCTI

### PCR
export PCR=23
python3 main_gcp.py --keyfile=rsatpm.pem \
 --email=$SERVICE_ACCOUNT_EMAIL --project_id=$PROJECT_ID \
  --pcr=$PCR --tcti=$TPM2TOOLS_TCTI
```

How it works:

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

So since we have the RSA key on the TPM, we can use the ESAPI to make it "sign" data for the JWT.

#### Setup - AWS

[AWS Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html) allows for client authentication based on digital signature from trusted private keys.

The trusted client RSA or EC key is embedded within a TPM and that is used to sign the RolesAnywhere header values.

In the example in this repo, we will use a *EXAMPLE* CA and key.  If you follow this setup, you are using the rsa key and CA found in this repo....so  *please* remember to use test resources and promptly delete/disable this.  You can find a sample setup using the link below and in this repo at `example/certs/alice-cert.key`.

Copy `example/certs/alice-cert.key` to `rsakey.pem` and run through the [Using RSA Keys on TPM](#using-rsa-keys-on-tpm) load step

The specific certificate CA and private key is the same as described in the sample here:

* [AWA RolesAnywhere Signer](https://github.com/salrashid123/aws_rolesanywhere_signer)

When you setup RolesAnywhere, note down the ARN for the `TrustAnchorArn`, `ProfileArn` and `RoleArn` as well as the `region`.  Ideally, the role has `AmazonS3ReadOnlyAccess` to list buckets.  If you want to use the script in this repo to embed the cert see the section above in using the `util/load.py` script

Then attempt to use the credentials and specify the specific ARN values

```bash
export CERTIFICATE="certs/alice-cert.crt"
export REGION="us-east-2"
export TRUST_ANCHOR_ARN="arn:aws:rolesanywhere:us-east-2:291738886522:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92ac"
export ROLE_ARN="arn:aws:iam::291738886522:role/rolesanywhere1"
export PROFILE_ARN="arn:aws:rolesanywhere:us-east-2:291738886522:profile/6f4943fb-13d4-4242-89c4-be367595c560"

pip3 install -r requirements-aws.txt

## Password
python3 main_aws.py --public_certificate_file=$CERTIFICATE \
   --region=$REGION  --trust_anchor_arn=$TRUST_ANCHOR_ARN \
     --role_arn=$ROLE_ARN \
          --profile_arn=$PROFILE_ARN \
            --keyfile=rsatpm.pem \
            --password=$KEY_PASSWORD \
            --tcti=$TPM2TOOLS_TCTI

### PCR
export PCR=23
python3 main_aws.py --public_certificate_file=$CERTIFICATE \
   --region=$REGION  --trust_anchor_arn=$TRUST_ANCHOR_ARN \
     --role_arn=$ROLE_ARN \
          --profile_arn=$PROFILE_ARN \
            --keyfile=rsatpm.pem \
            --pcr=$PCR \
            --tcti=$TPM2TOOLS_TCTI
```

Currently ONLY `RSASSA` keys are supported (its easy enough to support others, TODO)

An alternative to using this library is invoking a process to acquire credentials from any SDK.  See: [AWS Process Credentials for Trusted Platform Module (TPM)](https://github.com/salrashid123/aws-tpm-process-credential).


##### AWS HMAC

AWS supports HMAC based authentication as well. see: [AWS Credentials for Hardware Security Modules and TPM based AWS_SECRET_ACCESS_KEY](https://github.com/salrashid123/aws_hmac) and specifically [AWS v4 signed request using Trusted Platform Module](https://gist.github.com/salrashid123/bca7a24e1d59567adb89fef093d8564d)

This repo includes an example setup and to use this, you need your `AWS_ACCESS_KEY_ID` `AWS_SECRET_ACCESS_KEY` and embed the secret into the TPM and make it perform the HMAC

```bash
### first embed the hmac key
export AWS_ACCESS_KEY_ID=recacted
export AWS_SECRET_ACCESS_KEY=redacted
export TPM2TOOLS_TCTI="swtpm:port=2321"

## add the AWS4 prefix to the key per the signing protocol
export secret="AWS4$AWS_SECRET_ACCESS_KEY"
echo -n $secret > hmac.key

## create the h2 template
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

# embed the hmac key
tpm2_import -C primary.ctx -G hmac -i hmac.key -u hmac.pub -r hmac.prv  -p $KEY_PASSWORD

tpm2_load -C primary.ctx -u hmac.pub -r hmac.prv -c hmac.ctx 

### now convert the pub/priv to a PEM
cd util/
python3 load.py --public=hmac.pub --private=hmac.prv --out=hmac.pem --keyPassword=$KEY_PASSWORD # --tcti=$TPM2TOOLS_TCTI
```

To use this, you need to specify the key file and the `AWS_ACCESS_KEY_ID`
```bash
export REGION="us-east-1"

## for getsessiontoken
python3 main_aws_hmac.py --get_session_token=False \
   --region=$REGION  --aws_access_key_id=$AWS_ACCESS_KEY_ID \
             --keyfile=hmac.pem \
            --password=$KEY_PASSWORD \
            --tcti=$TPM2TOOLS_TCTI

## for assumerole
export ASSUME_ROLE_ARN="arn:aws:iam::291738886548:role/gcpsts"
python3 main_aws_hmac.py  --assume_role_arn=$ASSUME_ROLE_ARN --role_session_name=bar \
               --region=$REGION  --aws_access_key_id=$AWS_ACCESS_KEY_ID  \
                         --keyfile=hmac.pem \
                        --password=$KEY_PASSWORD \
                        --tcti=$TPM2TOOLS_TCTI
```

#### Setup - Azure

Azure authentication uses an the basic [Microsoft identity platform application authentication certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) where the variation here is that the client rsa key is on the TPM

The following example assumes you have set this up similar to

* [KMS, TPM and HSM based Azure Certificate Credentials](https://github.com/salrashid123/azsigner)

If you want to follow the instructions above and use the key provided in this repo, copy `example/certs/azclient.key"` to `rsakey.pem` and run through the [Using RSA Keys on TPM](#using-rsa-keys-on-tpm) load step


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

### Password
python3 main_azure.py --keyfile=rsatpm.pem \
   --certificate_path=$CERTIFICATE_PATH \
    --client_id=$CLIENT_ID  --tenant_id=$TENANT_ID \
    --password=$KEY_PASSWORD --tcti=$TPM2TOOLS_TCTI

### PCR
export PCR=23
python3 main_azure.py --keyfile=rsatpm.pem \
   --certificate_path=$CERTIFICATE_PATH \
    --client_id=$CLIENT_ID  --tenant_id=$TENANT_ID \
    --pcr=$PCR --tcti=$TPM2TOOLS_TCTI
```

Currently ONLY RSASSA  keys are supported (its easy enough to support others, TODO)

#### Custom Policy Implementation

The built repo contains a helper function which fulfills a `PCR` policy (i.,e certain PCR values must be present to use the key).

You can define your own class which fulfills any number of supported polcies as described in [TCG TSS 2.0 JSON Data Types and Policy LanguageSpecification](https://trustedcomputinggroup.org/wp-content/uploads/TSS_JSON_Policy_v0.7_r04_pubrev.pdf)


The way to do this is to implement an abstract class:

```python
from cloud_auth_tpm.policy.policy import PolicyEval
```

which requires you to pass in a policy json on init and then impelment whatever you need to do in `policy_callback(ectx)`, eg:


```python
class PolicyEval(object, metaclass=ABCMeta):
    def __init__(self, policy: dict[str, any] , debug: bool):

    @abstractmethod
    def policy_callback(self, ectx: ESAPI):
        pass
```

so for the built-in policy see [cloud_auth_tpm/policy/pcr.py](cloud_auth_tpm/policy/pcr.py).

Then to use it, fist import the policy (in this example, its the default `PCRPolicy`), supply it with the json format of the policy and specify it when invoking credentials.

eg, with 

```bash
$ tpm2_pcrread sha256:23
   sha256:
    23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

then define a pcr binding:

```python
from cloud_auth_tpm.policy import PCRPolicy

    pol = {
        "description": "Policy PCR 23 TPM2_ALG_SHA256",
        "policy": [
            {
                "type": "POLICYPCR",
                "pcrs": [
                    {
                        "pcr": 23,
                        "hashAlg": "TPM2_ALG_SHA256",
                        "digest": "F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B"
                    }
                ]
            }
        ]
    }
    pc = GCPCredentials(tcti=args.tcti,
                        keyfile=args.keyfile,
                        ownerpassword=args.ownerpassword,                        
                        password=args.password,
                        policy_impl=PCRPolicy(policy=pol),
                        email=args.email)
```

#### PEM Keyfile format

The TPM based keys are in PEM format compatible with openssl details of which you can find at [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html).

You can generate or convert TPM based keys on your own using openssl, [tpm2tss-genkey](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/man/tpm2tss-genkey.1.md) or [tpm2genkey](https://github.com/salrashid123/tpm2genkey)

decoded keys on TPM are readable as:

```bash
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
export TPM2OPENSSL_TCTI="swtpm:port=2321"

$ openssl rsa -provider tpm2  -provider default -in rsatpm.pem -text

Private-Key: (RSA 2048 bit, TPM 2.0)
Modulus:
    00:ec:26:5b:93:c6:09:b9:11:60:aa:d6:8f:21:6c:
    b5:6e:8a:52:30:b6:83:a1:0c:58:e7:61:ae:75:22:
    0d:8a:c9:da:dc:98:d0:32:20:a3:05:17:f4:c1:5d:
    06:f7:d7:05:09:81:e0:13:26:d7:be:74:53:4f:e0:
    e1:35:79:6e:bc:72:07:23:61:41:69:63:18:16:f4:
    27:8d:1c:33:31:59:61:6c:c1:76:f0:2c:e5:7c:e9:
    d4:d0:93:2b:07:27:77:10:2f:ab:c1:01:78:1c:27:
    68:e7:28:ba:ef:64:84:fe:62:2f:d4:f1:a8:ca:83:
    df:27:51:50:a3:b8:51:78:0b:04:be:d5:b5:43:a1:
    4c:89:fa:78:22:d6:45:50:f2:4a:1a:28:00:a5:6a:
    15:84:1b:46:51:de:2d:3c:65:c2:8b:9c:93:1d:53:
    da:4f:34:34:1f:b5:d3:d4:a7:81:aa:2b:44:80:b4:
    ff:58:51:2c:e7:cb:d4:53:18:ad:a3:49:81:9b:51:
    c5:4a:5d:f0:a7:7d:f7:eb:cc:00:89:13:9f:36:9e:
    8f:4d:23:7e:f2:36:dd:cb:cc:e3:b6:7b:b1:b9:4d:
    87:12:8a:33:2d:96:8c:c1:0a:6e:98:a3:54:29:98:
    86:79:97:33:42:6d:ca:e1:61:7b:bc:20:0d:30:54:
    92:3f
Exponent: 65537 (0x10001)
Object Attributes:
  userWithAuth
  sign / encrypt
Signature Scheme: PKCS1
  Hash: SHA256
writing RSA key
-----BEGIN TSS2 PRIVATE KEY-----
MIICNQYGZ4EFCgEDoAMBAQECBEAAAAEEggEaARgAAQALAAQAQAAAABAAFAALCAAA
AQABAQDsJluTxgm5EWCq1o8hbLVuilIwtoOhDFjnYa51Ig2KydrcmNAyIKMFF/TB
XQb31wUJgeATJte+dFNP4OE1eW68cgcjYUFpYxgW9CeNHDMxWWFswXbwLOV86dTQ
kysHJ3cQL6vBAXgcJ2jnKLrvZIT+Yi/U8ajKg98nUVCjuFF4CwS+1bVDoUyJ+ngi
1kVQ8koaKAClahWEG0ZR3i08ZcKLnJMdU9pPNDQftdPUp4GqK0SAtP9YUSzny9RT
GK2jSYGbUcVKXfCnfffrzACJE582no9NI37yNt3LzOO2e7G5TYcSijMtlozBCm6Y
o1QpmIZ5lzNCbcrhYXu8IA0wVJI/BIIBAAD+ACDBg/cpGTl++OOHhFwz+nBvPvNm
qdSNg+gqEzF1Eu2gNgAQ1qv0VDvcnIwo0DlItYWKfL7i1QHVMjp85eVgOGC8Qc65
VollWVse/DhTZOXz8N6qJhvXbj9HuRK2wdxka4mVjbAbgqNQdJfWbpyJk0d52hJ7
d71zvOwild71OLe/lvBqQlV3Hrk6Zvaed4C/38K3yPmICFR6YOfsFeDIAirzT+wp
9WGF9fq9CNzlKZgXAMoYLA6ZthtHKWdUUUYyyK0+yCqeNb32E5jN3Mn3GVxX9tc5
m5OgWpXX8bLqlRLY38P5J3HZOStjYxNBj5I3PdkvD7DFdlb7ZrJZoUg=
-----END TSS2 PRIVATE KEY-----
```

As a side note, although this is a private key in PEM format, this is NOT usable anywhere outside of that specific TPM and the actual private rsa/hmac key is never exposed outside of the TPM.

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

## swtpm don't have resource manager so you'll see "out of memory for object contexts" often...to clear the contexts:
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```
