# Control Testing Methodology

## Overview

This document describes the control testing approach used by the AWS Continuous Compliance Automation Framework.

The framework uses AWS APIs, Python, and boto3 to validate cloud security controls, collect evidence, assign risk ratings, and support audit-ready reporting.

The goal is to move beyond manual screenshots and point-in-time review by treating security and compliance controls as testable, repeatable, evidence-backed checks.

## Testing Approach

Each control follows a consistent testing workflow:

```text
Control objective
   ↓
AWS API evidence source
   ↓
Automated validation logic
   ↓
PASS / FAIL / ERROR result
   ↓
Structured evidence output
   ↓
Risk scoring
   ↓
Remediation or exception workflow
```

## Control Result Definitions

| Status | Meaning |
|---|---|
| PASS | The control condition was successfully evaluated and met the expected requirement. |
| FAIL | The control condition was successfully evaluated but did not meet the expected requirement. |
| ERROR | The control could not be evaluated due to permissions, service availability, API failure, missing input data, or another collection issue. |

## Evidence Collection Principles

The framework collects evidence directly from AWS APIs using boto3.

Evidence may include:

- AWS account-level security settings
- IAM user and credential metadata
- S3 bucket security configuration
- CloudTrail logging configuration
- GuardDuty detector status
- Security Hub subscription status
- IAM Access Analyzer findings
- IAM governance and access review data

Generated evidence is written to JSON and CSV formats.

## Evidence Output Design

The framework produces two primary evidence formats:

| Output | Purpose |
|---|---|
| JSON | Full structured technical evidence, including nested details for each evaluated control. |
| CSV | Flattened summary output for reporting, review, and audit workflows. |

JSON is intended for technical review and evidence traceability.

CSV is intended for GRC review, control owner review, and spreadsheet-friendly reporting.

## Risk Rating Approach

Each control is assigned a risk rating based on the potential impact of failure.

| Risk Rating | Meaning |
|---|---|
| Critical | Failure may create severe account compromise, data exposure, or major audit impact. |
| High | Failure may create significant security, access control, or compliance risk. |
| Medium | Failure may reduce visibility, governance, or security posture. |
| Low | Failure has limited direct impact but should be tracked. |

Risk ratings are used by the risk scoring module to prioritize failed controls.

## Control Testing Logic

Each control includes:

- Control ID
- Control domain
- Control objective
- AWS service
- Evidence source
- Test method
- PASS/FAIL/ERROR status
- Risk rating
- Timestamp
- Remediation guidance

Example:

| Field | Example |
|---|---|
| Control ID | IAM-001 |
| Control Name | Root MFA Enabled |
| AWS Service | IAM |
| Evidence Source | iam.get_account_summary |
| Expected Result | AccountMFAEnabled = 1 |
| Status | PASS or FAIL |
| Risk Rating | Critical |

## IAM Governance Testing

The IAM Governance module extends baseline AWS control testing into identity lifecycle and least-privilege drift detection.

IAM Governance controls evaluate:

- Stale IAM users
- Unused access keys
- Privileged IAM users
- Cross-account role trust relationships
- IAM Access Analyzer findings
- Quarterly access review evidence
- Leaver/offboarding validation

These checks support access review, credential hygiene, leaver validation, and privileged access governance.

## Leaver Validation Methodology

The leaver validation control compares a leaver source file against AWS IAM users.

The control supports identity correlation using:

1. Explicit IAM username
2. EmployeeId IAM user tag
3. Email IAM user tag

This avoids unreliable full-name matching and mirrors common IAM/IGA correlation patterns.

## Framework Mapping

Each control is mapped to one or more compliance or security frameworks, including:

- CIS AWS Foundations Benchmark
- NIST Cybersecurity Framework
- NIST SP 800-53
- SOC 2 Trust Services Criteria
- ISO/IEC 27001
- PCI DSS

The framework mapping is intended to show control alignment and audit relevance. It is not a formal auditor attestation.

## Evidence Handling

Generated evidence may contain sensitive or account-specific data, including:

- AWS account IDs
- IAM usernames
- ARNs
- Bucket names
- Access key metadata
- Security service configuration
- IAM tags
- Trust relationships

For that reason:

- Raw generated evidence is excluded from Git.
- Public samples should be sanitized.
- Evidence should be stored in a secured S3 evidence bucket.
- Evidence should be encrypted at rest.
- Access to evidence should follow least privilege.
- Evidence access should be logged when required by audit scope.

## Remediation and Exceptions

Failed controls should result in one of the following outcomes:

| Outcome | Description |
|---|---|
| Remediate | Fix the failed control and re-run the evidence collector. |
| Accept Risk | Document a business-approved exception with owner and expiration date. |
| Compensating Control | Document an alternative control that reduces the risk. |
| False Positive | Document why the result does not represent a true control failure. |

Exceptions should be tracked using the exception register template.

## Validation Cycle

Recommended validation cycle:

1. Run the evidence collector.
2. Review JSON and CSV evidence outputs.
3. Run the risk scoring module.
4. Review failed controls by severity.
5. Assign remediation owners.
6. Document exceptions where appropriate.
7. Re-run the collector after remediation.
8. Archive evidence securely.

## GRC Engineering Value

This methodology demonstrates how cloud security controls can be tested as code and converted into audit-ready evidence.

The framework supports:

- Continuous control monitoring
- Automated evidence collection
- Risk-based prioritization
- Access review workflows
- Remediation tracking
- Audit readiness
- Cloud governance at scale