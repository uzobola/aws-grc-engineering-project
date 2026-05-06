# AWS GRC Remediation Playbooks

## Overview

This document provides remediation guidance for failed controls identified by the AWS GRC Engineering evidence collector.

Each playbook includes:

- Control ID
- Risk rating
- Issue description
- Remediation action
- Validation method
- Evidence source

---

## IAM-003: IAM Users Have MFA

| Field | Details |
|---|---|
| Risk Rating | High |
| AWS Service | IAM |
| Control Domain | Identity and Access Management |
| Status | FAIL |

### Issue

One or more IAM users do not have MFA configured.

### Risk

IAM users without MFA are at higher risk of credential compromise. If credentials are phished, leaked, or reused, an attacker may authenticate without a second factor.

### Remediation

- Enable MFA for all IAM users.
- Prioritize users with console access or privileged permissions.
- Consider migrating human access to AWS IAM Identity Center or another federated identity provider.
- Enforce MFA centrally through the identity provider.

### Validation

Re-run the evidence collector and confirm:

```text
IAM-003 | IAM Users Have MFA | PASS | High
```

### Evidence Source

```text
iam.list_users + iam.list_mfa_devices
```

---

## DET-001: GuardDuty Enabled

| Field | Details |
|---|---|
| Risk Rating | High |
| AWS Service | GuardDuty |
| Control Domain | Threat Detection |
| Status | FAIL |

### Issue

Amazon GuardDuty is not enabled in the configured AWS region.

### Risk

Without GuardDuty, the account has reduced visibility into suspicious behavior, credential compromise indicators, reconnaissance activity, and malicious API activity.

### Remediation

- Enable Amazon GuardDuty in the required AWS region.
- For multi-account environments, configure delegated administration through AWS Organizations.
- Review GuardDuty findings regularly.
- Integrate findings with Security Hub or ticketing workflows.

### Validation

Re-run the evidence collector and confirm:

```text
DET-001 | GuardDuty Enabled | PASS | High
```

### Evidence Source

```text
guardduty.list_detectors + guardduty.get_detector
```

---

## SEC-001: Security Hub Enabled

| Field | Details |
|---|---|
| Risk Rating | Medium |
| AWS Service | Security Hub |
| Control Domain | Security Posture Management |
| Status | FAIL |

### Issue

AWS Security Hub is not enabled in the configured AWS region.

### Risk

Without Security Hub, security findings and compliance checks are not centrally aggregated. This reduces visibility into cloud security posture and slows remediation tracking.

### Remediation

- Enable AWS Security Hub.
- Enable relevant standards such as:
  - CIS AWS Foundations Benchmark
  - AWS Foundational Security Best Practices
  - PCI DSS, where applicable
- Integrate Security Hub findings with EventBridge, ticketing, or notification workflows.

### Validation

Re-run the evidence collector and confirm:

```text
SEC-001 | Security Hub Enabled | PASS | Medium
```

### Evidence Source

```text
securityhub.describe_hub
```