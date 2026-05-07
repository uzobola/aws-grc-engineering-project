# IAM Governance Methodology

## Overview

This module extends the AWS Continuous Compliance Automation Framework into IAM governance and least-privilege drift detection.

The goal is to connect AWS-native IAM telemetry with governance workflows such as access reviews, stale access detection, privilege review, cross-account trust review, and leaver validation.

## IAM Governance Objectives

This module focuses on identifying:

- Stale IAM users
- Unused access keys
- Privileged IAM users
- Risky cross-account trust relationships
- IAM Access Analyzer findings
- Access review evidence
- Leaver/offboarding validation gaps

## Why IAM Governance Matters

IAM risk often accumulates over time through role changes, temporary access, unused credentials, excessive permissions, and incomplete offboarding.

These issues create:

- Privilege creep
- Orphaned access
- Excessive permissions
- Audit findings
- Increased compromise impact

## Control Evaluation Pattern

Each IAM governance control follows the same pattern:

```text
AWS IAM telemetry
   ↓
Automated control evaluation
   ↓
Structured evidence output
   ↓
Risk scoring
   ↓
Access review or remediation action
```

## Initial Control

### IAM-004: Stale IAM Users

This control uses the AWS IAM credential report to identify IAM users with no recent password or access key activity.

A user is considered stale when no recent credential activity is observed within the configured threshold.

Default threshold:

```text
90 days
```

## Evidence Sources

- IAM Credential Report
- IAM Access Key Last Used data
- IAM role trust policies
- IAM policy attachments
- IAM Access Analyzer findings

## GRC Value

This module supports:

- Quarterly access reviews
- Leaver validation
- Least-privilege review
- Privileged access governance
- Identity lifecycle assurance
- Audit-ready access evidence