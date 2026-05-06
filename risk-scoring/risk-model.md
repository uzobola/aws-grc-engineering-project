# Risk Scoring Model

## Overview

This project uses a simple risk-based prioritization model to convert AWS control evidence into remediation priorities.

The goal is not to create a complex enterprise risk engine. The goal is to demonstrate how GRC Engineering can transform technical control results into business-readable risk insight.

## Risk Ratings

Each control in the control catalog has a risk rating:

| Risk Rating | Weight | Meaning |
|---|---:|---|
| Critical | 5 | Failure may create severe exposure, account compromise risk, or major audit impact |
| High | 4 | Failure may create significant security or compliance risk |
| Medium | 3 | Failure may reduce visibility, governance, or security posture |
| Low | 2 | Failure has limited direct impact but should be tracked |
| Informational | 1 | Used for awareness or documentation |

## Scoring Logic

The risk scoring script calculates:

- Total controls evaluated
- Passed controls
- Failed controls
- Error controls
- Compliance score percentage
- Failed controls grouped by risk rating
- Top remediation priorities

The compliance score is calculated as:

```text
passed_controls / total_controls_evaluated * 100