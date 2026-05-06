# AWS GRC Audit Evidence Report

## Report Purpose

This report documents automated evidence collected for AWS security and compliance controls.

The evidence was generated using Python and boto3 to query AWS APIs directly. This approach reduces reliance on manual screenshots and supports repeatable control validation.

## Evidence Collection Method

| Item | Description |
|---|---|
| Collection Method | Automated AWS API queries |
| Tooling | Python, boto3 |
| Evidence Outputs | JSON and CSV |
| Evidence Location | evidence-collector/output/ |
| Risk Summary | risk-scoring/output/risk-summary.json |
| Control Source | control-catalog/aws-control-catalog.csv |
| Framework Mapping | control-catalog/framework-mapping.csv |

## Control Testing Summary

| Control ID | Control Name | AWS Service | Status | Risk Rating | Evidence Source |
|---|---|---|---|---|---|
| IAM-001 | Root MFA Enabled | IAM | PASS | Critical | iam.get_account_summary |
| IAM-002 | No Active Root Access Keys | IAM | PASS | Critical | iam.get_account_summary |
| IAM-003 | IAM Users Have MFA | IAM | FAIL | High | iam.list_users + iam.list_mfa_devices |
| S3-001 | S3 Public Access Block Enabled | S3 | PASS | Critical | s3.list_buckets + s3.get_public_access_block |
| S3-002 | S3 Default Encryption Enabled | S3 | PASS | High | s3.list_buckets + s3.get_bucket_encryption |
| LOG-001 | CloudTrail Enabled | CloudTrail | PASS | Critical | cloudtrail.describe_trails + cloudtrail.get_trail_status |
| LOG-002 | CloudTrail Log File Validation Enabled | CloudTrail | PASS | High | cloudtrail.describe_trails |
| DET-001 | GuardDuty Enabled | GuardDuty | FAIL | High | guardduty.list_detectors + guardduty.get_detector |
| SEC-001 | Security Hub Enabled | Security Hub | FAIL | Medium | securityhub.describe_hub |

## Framework Alignment

This project includes mappings to the following frameworks:

- CIS AWS Foundations Benchmark
- NIST Cybersecurity Framework
- NIST SP 800-53
- SOC 2 Trust Services Criteria
- ISO/IEC 27001
- PCI DSS

## Evidence Handling Notes

Generated evidence files may contain AWS account-specific data such as account IDs, IAM usernames, bucket names, ARNs, and service configuration details.

For that reason:

- Evidence output is excluded from Git version control.
- Evidence should be stored in a secured S3 evidence bucket.
- Access to evidence should be restricted using least privilege.
- Evidence should be encrypted at rest.
- Evidence access should be logged when required by audit scope.

## Failed Controls

### IAM-003: IAM Users Have MFA

**Status:** FAIL  
**Risk Rating:** High  
**Control Objective:** Ensure IAM users are protected with multi-factor authentication.

**Risk:** IAM users without MFA are more vulnerable to credential compromise.

**Remediation:** Enable MFA for all IAM users or migrate access to a federated identity provider with enforced MFA.

---

### DET-001: GuardDuty Enabled

**Status:** FAIL  
**Risk Rating:** High  
**Control Objective:** Ensure threat detection is enabled in the AWS account.

**Risk:** Without GuardDuty, the account has reduced ability to detect malicious behavior, compromised credentials, suspicious API activity, and reconnaissance attempts.

**Remediation:** Enable Amazon GuardDuty in required regions.

---

### SEC-001: Security Hub Enabled

**Status:** FAIL  
**Risk Rating:** Medium  
**Control Objective:** Ensure centralized security posture management is enabled.

**Risk:** Without Security Hub, security findings and compliance checks are not centrally aggregated.

**Remediation:** Enable AWS Security Hub and configure relevant standards.

## Audit Conclusion

The automated control validation process successfully generated evidence for AWS identity, data protection, logging, threat detection, and security posture controls.

The current environment has a strong baseline for root account security, S3 protection, and CloudTrail logging. Remediation is required for IAM user MFA, GuardDuty, and Security Hub to improve overall security and compliance posture.