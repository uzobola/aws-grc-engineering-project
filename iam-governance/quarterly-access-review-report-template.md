# Quarterly IAM Access Review Report

## Report Purpose

This report provides a review-ready summary of IAM access posture based on automated AWS IAM governance checks.

## Review Scope

| Item | Description |
|---|---|
| Cloud Provider | AWS |
| Review Type | IAM Governance Access Review |
| Evidence Source | AWS IAM Credential Report and IAM APIs |
| Review Frequency | Quarterly |
| Control Domains | Identity Lifecycle, Access Management, Privileged Access |

## Review Summary

| Metric | Value |
|---|---:|
| IAM Users Reviewed | TBD |
| Stale IAM Users | TBD |
| Unused Access Keys | TBD |
| Privileged IAM Users | TBD |
| Cross-Account Trust Findings | TBD |
| Access Analyzer Findings | TBD |

## Key Review Questions

- Are all IAM users still required?
- Are any IAM users inactive or stale?
- Are any access keys unused or overdue for rotation?
- Are privileged users still authorized?
- Are cross-account trust relationships approved?
- Are Access Analyzer findings reviewed and remediated?
- Are leaver records reflected in AWS IAM access?

## Review Outcome

| Control ID | Control Name | Status | Reviewer Decision |
|---|---|---|---|
| IAM-004 | Stale IAM Users | TBD | Pending |
| IAM-005 | Unused Access Keys | TBD | Pending |
| IAM-006 | Privileged IAM Users | TBD | Pending |
| IAM-007 | Cross-Account Role Trust Review | TBD | Pending |
| IAM-008 | IAM Access Analyzer Findings | TBD | Pending |

## Evidence Handling

Generated access review evidence may contain IAM usernames, ARNs, account IDs, and credential metadata.

For that reason, raw evidence should be stored securely, encrypted at rest, and excluded from public repositories.

## Reviewer Sign-Off

| Reviewer | Role | Decision | Date |
|---|---|---|---|
| TBD | Control Owner | Pending | TBD |