# AWS Continuous Compliance Automation Framework

<h1 align="center">AWS Continuous Compliance Automation Framework</h1>

<p align="center">
  <img src="assets/aws-continuous-compliance-framework.png" alt="AWS Continuous Compliance Automation Framework" width="900">
</p>

An AWS GRC Engineering implementation for automated control validation, compliance evidence collection, risk-based remediation prioritization, and audit-ready reporting.

## Overview

This project demonstrates an engineering-driven approach to Governance, Risk, and Compliance in AWS. It focuses on continuous control monitoring, automated evidence collection, compliance framework mapping, risk scoring, and audit-ready reporting across common AWS security domains.

The goal is to show how AWS security telemetry can be transformed into continuous compliance evidence and actionable risk insight.


## Why This Matters

Traditional compliance evidence collection often relies on screenshots, manual reviews, spreadsheets, and point-in-time audits. This approach does not scale well in dynamic cloud environments where resources and configurations can change quickly.

This project shows how AWS security controls can be validated through APIs, converted into structured evidence, mapped to compliance frameworks, scored by risk, and reported in audit-ready formats.

The result is a repeatable GRC Engineering workflow that supports continuous assurance instead of manual audit preparation.


## Business Problem

Cloud environments change quickly, but many compliance programs still rely on manual evidence collection, screenshots, spreadsheets, and point-in-time audits. This creates delays, inconsistent evidence, limited visibility, and increased risk of control drift.

## Solution

This project implements a lightweight AWS GRC Engineering workflow that:

- Defines a reusable AWS security control catalog
- Maps technical AWS controls to compliance frameworks
- Uses Python and boto3 to collect evidence from AWS APIs
- Scores findings by risk severity
- Produces audit-ready evidence outputs
- Provides remediation guidance for failed controls
- Implements a controls-as-code approach so GRC requirements are tested and evidenced automatically rather than manually

## Control Domains

- Identity and Access Management
- Logging and Monitoring
- Data Protection
- Threat Detection
- Security Posture Management

## Framework Alignment

This project includes control mapping examples for:

- CIS AWS Foundations Benchmark
- NIST Cybersecurity Framework
- NIST SP 800-53
- SOC 2 Trust Services Criteria
- ISO/IEC 27001
- PCI DSS

## Project Status

Core implementation completed.

This project now includes:

- AWS control catalog
- Compliance framework mapping
- Automated evidence collection using Python and boto3
- IAM, S3, CloudTrail, GuardDuty, and Security Hub control checks
- JSON and CSV evidence output
- Risk scoring model
- Executive summary template
- Audit evidence report template
- Remediation playbooks
- Exception register template
- Secure S3 evidence bucket automation script

## Repository Structure

```text
aws-grc-engineering-project/
├── control-catalog/
│   ├── aws-control-catalog.csv
│   ├── framework-mapping.csv
│   └── control-testing-methodology.md
├── evidence-collector/
│   ├── config.yaml
│   ├── requirements.txt
│   └── src/
│       ├── main.py
│       ├── checks/
│       ├── evidence/
│       └── utils/
├── remediation/
│   ├── remediation-playbooks.md
│   └── exception-register-template.csv
├── reports/
│   ├── executive-summary-template.md
│   └── audit-evidence-report-template.md
├── risk-scoring/
│   ├── risk_score.py
│   └── risk-model.md
├── scripts/
│   ├── create-evidence-bucket.sh
│   └── create-evidence-bucket-with-cmk.sh
├── .gitignore
└── README.md
```

## Tech Stack

- AWS: IAM, S3, CloudTrail, GuardDuty, Security Hub
- Language: Python
- SDK: boto3
- Evidence Outputs: JSON and CSV
- Reporting: Markdown templates
- Automation: Bash scripts
- Version Control: Git and GitHub

## Implemented Controls

| Control ID | Control Name | Domain | AWS Service | Status |
|---|---|---|---|---|
| IAM-001 | Root MFA Enabled | Identity and Access Management | IAM | Implemented |
| IAM-002 | No Active Root Access Keys | Identity and Access Management | IAM | Implemented |
| IAM-003 | IAM Users Have MFA | Identity and Access Management | IAM | Implemented |
| S3-001 | S3 Public Access Block Enabled | Data Protection | S3 | Implemented |
| S3-002 | S3 Default Encryption Enabled | Data Protection | S3 | Implemented |
| LOG-001 | CloudTrail Enabled | Logging and Monitoring | CloudTrail | Implemented |
| LOG-002 | CloudTrail Log File Validation Enabled | Logging and Monitoring | CloudTrail | Implemented |
| DET-001 | GuardDuty Enabled | Threat Detection | GuardDuty | Implemented |
| SEC-001 | Security Hub Enabled | Security Posture Management | Security Hub | Implemented |

## How to Run the Evidence Collector

From the project root:

```bash
cd evidence-collector
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
python src/main.py
```

The collector generates:

```text
output/evidence-results.json
output/evidence-results.csv
```

Generated evidence output is excluded from Git because it may contain AWS account-specific data.

## How to Run Risk Scoring

After running the evidence collector:

```bash
cd ../risk-scoring
python risk_score.py
```

The risk scoring module generates:

```text
risk-scoring/output/risk-summary.json
```

## How to Create a Secure Evidence Bucket

This project includes a script to create a hardened S3 bucket for storing generated GRC evidence.

Default AES256 encryption:

```bash
./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer
```

SSE-KMS with a customer-managed KMS key:

```bash
./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer arn:aws:kms:us-east-1:123456789012:key/example-key-id
```

Strict encryption enforcement mode:

```bash
./scripts/create-evidence-bucket-with-cmk.sh my-evidence-bucket us-east-1 grc-engineer arn:aws:kms:us-east-1:123456789012:key/example-key-id strict
```

The script applies public access blocking, object ownership enforcement, versioning, encryption, TLS-only bucket policy guardrails, and project tags.


## Sample Assessment Result

Example control posture from the assessment environment:

| Metric | Value |
|---|---:|
| Total Controls Evaluated | 9 |
| Passed Controls | 6 |
| Failed Controls | 3 |
| Error Controls | 0 |
| Compliance Score | 66.67% |

Example failed controls:

| Control ID | Control Name | Risk |
|---|---|---|
| IAM-003 | IAM Users Have MFA | High |
| DET-001 | GuardDuty Enabled | High |
| SEC-001 | Security Hub Enabled | Medium |

## GRC Engineering Concepts Demonstrated

This project demonstrates:

- Continuous control monitoring
- Automated evidence collection
- Control-to-framework mapping
- Risk-based finding prioritization
- Audit-ready reporting
- Remediation playbooks
- Exception tracking
- Secure evidence storage design
- Separation of generated evidence from source code

## Security and Evidence Handling

Generated evidence files may include AWS account IDs, IAM usernames, bucket names, ARNs, and configuration details.

For that reason:

- Evidence output is excluded from version control
- Evidence should be stored in a secured S3 evidence bucket
- Access should follow least privilege
- Evidence should be encrypted at rest
- Evidence access should be logged when required by audit scope

## Future Enhancements

- AWS Config integration
- Security Hub findings ingestion
- Multi-account support using AWS Organizations
- Automated remediation with Lambda
- HTML or dashboard reporting
- Jira or ServiceNow ticket generation
- IAM Access Analyzer evidence checks
- KMS key governance checks

## Sample Screenshots

The screenshots below show the evidence collector and risk scoring module running against a dedicated AWS assessment account. Sensitive account-specific evidence is excluded from the repository; only sanitized summary output is shown.

### Evidence Collector Output

![Evidence Collector Output](samples/screenshots/evidence-collector-terminal.png)

### Risk Scoring Output

![Risk Scoring Output](samples/screenshots/risk-scoring-terminal.png)

## Author

Created by Uzo Bolarinwa as a practical AWS GRC Engineering implementation focused on automated control validation, compliance evidence collection, risk-based reporting, and cloud security governance.
