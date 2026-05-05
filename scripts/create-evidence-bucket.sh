#!/usr/bin/env bash

set -euo pipefail

# ------------------------------------------------------------
# AWS GRC Engineering Project
# Secure S3 Evidence Bucket Creation Script
#
# Purpose:
# Creates a hardened S3 bucket for storing GRC evidence artifacts.
#
# Controls implemented:
# - Public access blocked
# - Object ownership enforced / ACLs disabled
# - Default encryption enabled
# - Optional SSE-KMS support
# - Versioning enabled
# - Bucket policy guardrails
#   - Deny non-TLS requests
#   - Deny unencrypted uploads
#   - Deny incorrect encryption algorithm
# - Project tags applied
#
# Usage:
# ./scripts/create-evidence-bucket.sh <bucket-name> <region> <aws-profile> [kms-key-id]
#
# Examples:
# AES256 encryption:
# ./scripts/create-evidence-bucket.sh uzo-aws-grc-evidence-2025 us-east-1 grc-engineer
#
# SSE-KMS encryption:
# ./scripts/create-evidence-bucket.sh uzo-aws-grc-evidence-2025 us-east-1 grc-engineer arn:aws:kms:us-east-1:123456789012:key/example-key-id
# ------------------------------------------------------------

BUCKET_NAME="${1:-}"
REGION="${2:-us-east-1}"
PROFILE="${3:-grc-engineer}"
KMS_KEY_ID="${4:-}"

if [[ -z "$BUCKET_NAME" ]]; then
  echo "ERROR: Bucket name is required."
  echo "Usage: ./scripts/create-evidence-bucket.sh <bucket-name> <region> <aws-profile> [kms-key-id]"
  exit 1
fi

echo "Starting secure evidence bucket setup..."
echo "Bucket:  $BUCKET_NAME"
echo "Region:  $REGION"
echo "Profile: $PROFILE"

if [[ -n "$KMS_KEY_ID" ]]; then
  echo "Encryption: SSE-KMS"
  echo "KMS Key: $KMS_KEY_ID"
else
  echo "Encryption: SSE-S3 AES256"
fi

echo

echo "Verifying AWS identity..."
aws sts get-caller-identity --profile "$PROFILE"
echo

echo "Checking if bucket already exists..."

if aws s3api head-bucket --bucket "$BUCKET_NAME" --profile "$PROFILE" 2>/dev/null; then
  echo "Bucket already exists and is accessible: $BUCKET_NAME"
  echo "Continuing to apply security controls..."
else
  echo "Bucket does not exist or is not accessible. Attempting to create..."

  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket \
      --bucket "$BUCKET_NAME" \
      --region "$REGION" \
      --object-ownership BucketOwnerEnforced \
      --profile "$PROFILE"
  else
    aws s3api create-bucket \
      --bucket "$BUCKET_NAME" \
      --region "$REGION" \
      --create-bucket-configuration LocationConstraint="$REGION" \
      --object-ownership BucketOwnerEnforced \
      --profile "$PROFILE"
  fi

  echo "Bucket created successfully."
fi

echo

echo "Enforcing bucket owner object ownership and disabling ACL usage..."

aws s3api put-bucket-ownership-controls \
  --bucket "$BUCKET_NAME" \
  --ownership-controls '{
    "Rules": [
      {
        "ObjectOwnership": "BucketOwnerEnforced"
      }
    ]
  }' \
  --profile "$PROFILE"

echo "Object ownership enforced."
echo

echo "Blocking all public access..."

aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile "$PROFILE"

echo "Public access block applied."
echo

echo "Enabling default server-side encryption..."

if [[ -n "$KMS_KEY_ID" ]]; then
  aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration "{
      \"Rules\": [
        {
          \"ApplyServerSideEncryptionByDefault\": {
            \"SSEAlgorithm\": \"aws:kms\",
            \"KMSMasterKeyID\": \"$KMS_KEY_ID\"
          },
          \"BucketKeyEnabled\": true
        }
      ]
    }" \
    --profile "$PROFILE"

  REQUIRED_ENCRYPTION_ALGORITHM="aws:kms"
else
  aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
      "Rules": [
        {
          "ApplyServerSideEncryptionByDefault": {
            "SSEAlgorithm": "AES256"
          }
        }
      ]
    }' \
    --profile "$PROFILE"

  REQUIRED_ENCRYPTION_ALGORITHM="AES256"
fi

echo "Default encryption enabled."
echo

echo "Enabling bucket versioning..."

aws s3api put-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --versioning-configuration Status=Enabled \
  --profile "$PROFILE"

echo "Versioning enabled."
echo

echo "Applying bucket policy guardrails..."

cat > /tmp/evidence-bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$BUCKET_NAME",
        "arn:aws:s3:::$BUCKET_NAME/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyIncorrectEncryptionAlgorithm",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "$REQUIRED_ENCRYPTION_ALGORITHM"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --policy file:///tmp/evidence-bucket-policy.json \
  --profile "$PROFILE"

rm -f /tmp/evidence-bucket-policy.json

echo "Bucket policy guardrails applied."
echo

echo "Applying bucket tags..."

aws s3api put-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --tagging '{
    "TagSet": [
      {
        "Key": "Project",
        "Value": "aws-grc-engineering-project"
      },
      {
        "Key": "Purpose",
        "Value": "GRC Evidence Storage"
      },
      {
        "Key": "DataClassification",
        "Value": "Internal"
      },
      {
        "Key": "ManagedBy",
        "Value": "Automation"
      },
      {
        "Key": "ControlBaseline",
        "Value": "EvidenceStorage"
      }
    ]
  }' \
  --profile "$PROFILE"

echo "Tags applied."
echo

echo "Verifying bucket security controls..."
echo

echo "Public Access Block:"
aws s3api get-public-access-block \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE"

echo
echo "Ownership Controls:"
aws s3api get-bucket-ownership-controls \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE"

echo
echo "Encryption:"
aws s3api get-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE"

echo
echo "Versioning:"
aws s3api get-bucket-versioning \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE"

echo
echo "Bucket Policy:"
aws s3api get-bucket-policy \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE" \
  --query Policy \
  --output text

echo
echo "Bucket Tags:"
aws s3api get-bucket-tagging \
  --bucket "$BUCKET_NAME" \
  --profile "$PROFILE"

echo
echo "Secure evidence bucket setup complete."
echo "S3 URI: s3://$BUCKET_NAME"
