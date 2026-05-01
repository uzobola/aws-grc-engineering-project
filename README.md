# AWS GRC Engineering Project

## Overview

This project demonstrates an engineering-driven approach to Governance, Risk, and Compliance in AWS. It focuses on continuous control monitoring, automated evidence collection, compliance framework mapping, risk scoring, and audit-ready reporting across common AWS security domains.

The goal is to show how AWS security telemetry can be transformed into continuous compliance evidence and actionable risk insight.

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

## Current Project Status

Phase 1 is focused on building the foundational GRC artifacts:

- AWS control catalog
- Framework mapping
- Control testing methodology
- Evidence collector structure
- Risk scoring model
- Remediation workflow templates

## Repository Structure

```text
aws-grc-engineering-project/
├── control-catalog/
├── evidence-collector/
├── remediation/
├── reports/
├── risk-scoring/
├── .gitignore
└── README.md
```

## Planned Capabilities

- Automated IAM evidence collection
- S3 security control validation
- CloudTrail logging validation
- GuardDuty and Security Hub posture checks
- JSON/CSV evidence output
- Risk-based finding prioritization
- Audit-ready reporting templates
- Remediation and exception tracking

## Author

Built by Uzo Bolarinwa as part of a hands-on AWS GRC Engineering portfolio focused on cloud security, compliance automation, and security controls.
