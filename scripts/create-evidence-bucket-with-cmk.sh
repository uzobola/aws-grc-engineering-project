#!/usr/bin/env bash

set -euo pipefail

# ------------------------------------------------------------
# AWS GRC Engineering Project
# Secure S3 Evidence Bucket Creation Script (with CMK support)
#
# Purpose:
# Creates a hardened S3 bucket for GRC evidence with:
# - Public access blocked
# - Object ownership enforced (ACLs disabled)
# - Versioning enabled
# - TLS-only access policy
# - Encryption guardrails
#   - Compatibility mode (default): default bucket encryption only
#   - Strict mode: enforce client-provided SSE headers
# - Optional SSE-KMS with customer-managed key (CMK)
#
# Usage:
# ./scripts/create-evidence-bucket-with-cmk.sh <bucket-name> [region] [aws-profile] [kms-key-arn] [strict|compat]
#
# Examples:
# AES256 compat mode:
# ./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer
#
# AES256 strict mode:
# ./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer "" strict
#
# KMS compat mode:
# ./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer arn:aws:kms:us-east-1:123456789012:key/abcd-1234
#
# KMS strict mode:
# ./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer arn:aws:kms:us-east-1:123456789012:key/abcd-1234 strict
# ------------------------------------------------------------

BUCKET_NAME="${1:-}"
REGION="${2:-us-east-1}"
PROFILE="${3:-grc-engineer}"
KMS_KEY_ARN="${4:-}"
ENFORCEMENT_MODE="${5:-compat}" # compat | strict

if [[ -z "${BUCKET_NAME}" ]]; then
  echo "ERROR: Bucket name is required."
  echo "Usage: $0 <bucket-name> [region] [aws-profile] [kms-key-arn] [strict|compat]"
  exit 1
fi

if [[ "${ENFORCEMENT_MODE}" != "compat" && "${ENFORCEMENT_MODE}" != "strict" ]]; then
  echo "ERROR: enforcement mode must be 'compat' or 'strict'"
  exit 1
fi

if [[ -n "${KMS_KEY_ARN}" && "${KMS_KEY_ARN}" != arn:aws:kms:* ]]; then
  echo "ERROR: kms-key-arn must look like arn:aws:kms:..."
  exit 1
fi

echo "Starting secure evidence bucket setup..."
echo "Bucket:      ${BUCKET_NAME}"
echo "Region:      ${REGION}"
echo "Profile:     ${PROFILE}"
echo "Mode:        ${ENFORCEMENT_MODE}"

if [[ -n "${KMS_KEY_ARN}" ]]; then
  echo "Encryption:  SSE-KMS (CMK)"
  echo "KMS Key ARN: ${KMS_KEY_ARN}"
  REQUIRED_ENCRYPTION_ALGORITHM="aws:kms"
else
  echo "Encryption:  SSE-S3 (AES256)"
  REQUIRED_ENCRYPTION_ALGORITHM="AES256"
fi
echo

echo "Verifying AWS identity..."
aws sts get-caller-identity --profile "${PROFILE}"
echo

echo "Checking if bucket already exists and is accessible..."
if aws s3api head-bucket --bucket "${BUCKET_NAME}" --profile "${PROFILE}" 2>/dev/null; then
  echo "Bucket exists and is accessible: ${BUCKET_NAME}"
else
  echo "Bucket not accessible via this profile; attempting create..."

  if [[ "${REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket \
      --bucket "${BUCKET_NAME}" \
      --region "${REGION}" \
      --object-ownership BucketOwnerEnforced \
      --profile "${PROFILE}"
  else
    aws s3api create-bucket \
      --bucket "${BUCKET_NAME}" \
      --region "${REGION}" \
      --create-bucket-configuration LocationConstraint="${REGION}" \
      --object-ownership BucketOwnerEnforced \
      --profile "${PROFILE}"
  fi

  echo "Bucket created."
fi
echo

echo "Enforcing bucket owner object ownership (disables ACLs)..."
aws s3api put-bucket-ownership-controls \
  --bucket "${BUCKET_NAME}" \
  --ownership-controls '{
    "Rules": [
      {
        "ObjectOwnership": "BucketOwnerEnforced"
      }
    ]
  }' \
  --profile "${PROFILE}"
echo "Ownership controls applied."
echo

echo "Blocking all public access..."
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile "${PROFILE}"
echo "Public access block applied."
echo

echo "Configuring default encryption..."
if [[ -n "${KMS_KEY_ARN}" ]]; then
  aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration "{
      \"Rules\": [
        {
          \"ApplyServerSideEncryptionByDefault\": {
            \"SSEAlgorithm\": \"aws:kms\",
            \"KMSMasterKeyID\": \"${KMS_KEY_ARN}\"
          },
          \"BucketKeyEnabled\": true
        }
      ]
    }" \
    --profile "${PROFILE}"
else
  aws s3api put-bucket-encryption \
    --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration '{
      "Rules": [
        {
          "ApplyServerSideEncryptionByDefault": {
            "SSEAlgorithm": "AES256"
          }
        }
      ]
    }' \
    --profile "${PROFILE}"
fi
echo "Default encryption applied."
echo

echo "Enabling versioning..."
aws s3api put-bucket-versioning \
  --bucket "${BUCKET_NAME}" \
  --versioning-configuration Status=Enabled \
  --profile "${PROFILE}"
echo "Versioning enabled."
echo

echo "Building bucket policy..."
POLICY_FILE="$(mktemp "/tmp/${BUCKET_NAME}.policy.XXXXXX.json")"
cleanup() {
  rm -f "${POLICY_FILE}"
}
trap cleanup EXIT

if [[ "${ENFORCEMENT_MODE}" == "compat" ]]; then
  cat > "${POLICY_FILE}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF
else
  if [[ -n "${KMS_KEY_ARN}" ]]; then
    cat > "${POLICY_FILE}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyMissingEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyWrongEncryptionAlgorithm",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyWrongKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "${KMS_KEY_ARN}"
        }
      }
    }
  ]
}
EOF
  else
    cat > "${POLICY_FILE}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::${BUCKET_NAME}",
        "arn:aws:s3:::${BUCKET_NAME}/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyMissingEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyWrongEncryptionAlgorithm",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
EOF
  fi
fi

echo "Applying bucket policy..."
aws s3api put-bucket-policy \
  --bucket "${BUCKET_NAME}" \
  --policy "file://${POLICY_FILE}" \
  --profile "${PROFILE}"
echo "Bucket policy applied."
echo

echo "Applying tags..."
aws s3api put-bucket-tagging \
  --bucket "${BUCKET_NAME}" \
  --tagging '{
    "TagSet": [
      {"Key": "Project", "Value": "aws-grc-engineering-project"},
      {"Key": "Purpose", "Value": "GRC Evidence Storage"},
      {"Key": "DataClassification", "Value": "Internal"},
      {"Key": "ManagedBy", "Value": "Automation"},
      {"Key": "ControlBaseline", "Value": "EvidenceStorage"}
    ]
  }' \
  --profile "${PROFILE}"
echo "Tags applied."
echo

echo "Verifying controls..."
echo "Public Access Block:"
aws s3api get-public-access-block --bucket "${BUCKET_NAME}" --profile "${PROFILE}"
echo

echo "Ownership Controls:"
aws s3api get-bucket-ownership-controls --bucket "${BUCKET_NAME}" --profile "${PROFILE}"
echo

echo "Encryption:"
aws s3api get-bucket-encryption --bucket "${BUCKET_NAME}" --profile "${PROFILE}"
echo

echo "Versioning:"
aws s3api get-bucket-versioning --bucket "${BUCKET_NAME}" --profile "${PROFILE}"
echo

echo "Bucket Policy:"
aws s3api get-bucket-policy --bucket "${BUCKET_NAME}" --profile "${PROFILE}" --query Policy --output text
echo

echo "Bucket Tags:"
aws s3api get-bucket-tagging --bucket "${BUCKET_NAME}" --profile "${PROFILE}"
echo

echo "Secure evidence bucket setup complete."
echo "S3 URI: s3://${BUCKET_NAME}"
