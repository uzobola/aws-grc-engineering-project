variable "aws_region" {
  type        = string
  description = "AWS region where the evidence vault will be deployed."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Short project identifier used in the evidence vault bucket name."
  default     = "aws-grc"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumeric characters or hyphens, starting with a letter."
  }
}

variable "lock_mode" {
  type        = string
  description = "Object Lock retention mode. Use GOVERNANCE for labs and COMPLIANCE for production evidence."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default object retention period in days."
  default     = 1

  validation {
    condition     = var.retention_days >= 1
    error_message = "retention_days must be at least 1."
  }
}