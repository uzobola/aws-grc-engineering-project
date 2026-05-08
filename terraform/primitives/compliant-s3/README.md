# Compliant S3 Terraform Primitive

## Overview

This Terraform primitive deploys a compliant S3 bucket pattern for AWS GRC evidence and control validation.

It creates:

- Primary S3 bucket
- S3 server access log bucket
- Default server-side encryption
- Versioning
- Full public access blocking
- Server access logging
- Required compliance tags
- Machine-readable Terraform outputs

## Control Alignment

| Control Family | Implementation |
|---|---|
| SC-28 | S3 default encryption at rest using AES256 |
| AU-3 | Server access logging captures access activity |
| AU-6 | Logs support audit review and investigation |
| CM-6 | Required compliance tags applied through Terraform provider defaults |
| AC-3 | S3 public access block enforces access control baseline |

## Why This Matters

This module demonstrates preventive compliance engineering. Instead of only detecting misconfigurations after deployment, the Terraform primitive builds compliant infrastructure from the start.

This complements the evidence collector by showing both sides of GRC Engineering:

```text
Preventive control design with Terraform
   ↓
Detective control validation with AWS APIs
   ↓
Evidence generation and risk scoring
```

## Usage

From this directory:

```bash
terraform init
terraform validate
terraform plan -out=tfplan \
  -var="project_name=grcframework" \
  -var="environment=dev"

terraform apply -auto-approve tfplan
```

## Inputs

| Variable | Description | Default |
|---|---|---|
| `aws_region` | AWS region where the compliant S3 primitive will be deployed | `us-east-1` |
| `project_name` | Short project identifier used in bucket names and tags | Required |
| `environment` | Deployment environment. Must be `dev`, `staging`, or `prod` | Required |
| `bucket_suffix` | Optional suffix to force a specific bucket name. Defaults to a random suffix | `""` |

## Outputs

| Output | Description |
|---|---|
| `bucket_name` | Name of the compliant primary S3 bucket |
| `bucket_arn` | ARN of the compliant primary S3 bucket |
| `log_bucket_name` | Name of the S3 server access logging bucket |
| `log_bucket_arn` | ARN of the S3 server access logging bucket |
| `encryption_algorithm` | Server-side encryption algorithm used for the primary bucket |
| `compliance_attestation` | Machine-readable compliance attestation for the S3 primitive |

## Evidence Generation

Generate machine-readable Terraform evidence:

```bash
mkdir -p evidence
terraform show -json tfplan > evidence/plan.json
terraform show -json > evidence/state.json
terraform output -json > evidence/outputs.json
```

These files can be uploaded to the evidence vault for retention and auditor review.

## Verification

After deployment, verify the bucket controls with AWS CLI:

```bash
BUCKET=$(terraform output -raw bucket_name)

aws s3api get-bucket-encryption --bucket "$BUCKET"
aws s3api get-bucket-versioning --bucket "$BUCKET"
aws s3api get-public-access-block --bucket "$BUCKET"
```

Expected results:

- Default encryption is enabled with `AES256`
- Versioning is enabled
- All four S3 public access block settings are `true`

## GRC Engineering Value

This primitive demonstrates how compliance requirements can be embedded directly into infrastructure provisioning.

It supports:

- Preventive control design
- Controls as code
- Machine-readable evidence
- Repeatable compliant infrastructure
- Reduced control drift
- Audit-ready Terraform outputs

## Cleanup

```bash
terraform destroy -auto-approve \
  -var="project_name=grcframework" \
  -var="environment=dev"
```

If the log bucket contains objects, empty it before destroying.

## Notes

S3 bucket names are globally unique. If a bucket name conflict occurs, use a different `project_name`, `environment`, or `bucket_suffix`.

For production use, consider replacing AES256 with SSE-KMS using a customer-managed KMS key and adding lifecycle rules for log retention.