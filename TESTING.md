### Testing

The test suite verifies live access to cloud providers.

You need to setup each of these providers to verify/test locally (which isn't all that easy).

So


```bash
export CICD_SA_PEM=`cat /path/to/service-account.json | jq -r '.private_key'`
export CICD_SA_EMAIL="cicd-test-sa@your_cicdproject.iam.gserviceaccount.com"
export CICD_SA_PROJECT="your_cicdproject"
export CICD_BUCKET="your-cicd-test-bucket"

export CICD_AWS_ACCESS_KEY=AKIAUH3H-reddacted
export CICD_AWS_ACCESS_SECRET=redacted


export CICD_AWS_PEM=`cat /path/to/awsclient.key`
export CICD_AWS_CERT=`cat /path/to/awsclient.crt`
export CICD_AWS_REGION="us-east-2"
export CICD_AWS_TRUST_ANCHOR_ARN="arn:aws:rolesanywhere:us-east-2:redacted:trust-anchor/746378c7-ffac-4d5b-991c-redacted"
export CICD_AWS_ROLE_ARN="arn:aws:iam::291738886548:role/cicd-role"
export CICD_AWS_PROFILE_ARN="arn:aws:rolesanywhere:us-east-2:redacted:profile/89cd63fa-169c-4049-bcbc-redacted"
export CICD_AWS_HMAC_REGION="us-east-1"


export CICD_AZURE_CLIENT_ID=redacted-5617-4784-8a4b-redacted
export CICD_AZURE_TENANT_ID=redacted-b73f-4f7d-8213-redacted
export CICD_AZURE_STORAGEACCOUNT=your_bucket
export CICD_AZURE_CONTAINER=your_container
export CICD_AZURE_CLIENT_PEM=`cat /path/to/azureclient.key`
export CICD_AZURE_CERT=`cat /path/to/azureclient.crt
```