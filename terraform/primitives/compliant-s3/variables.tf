variable "aws_region" {
  type        = string
  description = "AWS region where the compliant S3 primitive will be deployed."
  default     = "us-east-1"
}

variable "project_name" {
  type        = string
  description = "Short project identifier used in bucket names and tags."

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumeric characters or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment."

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "bucket_suffix" {
  type        = string
  description = "Optional suffix to force a specific bucket name. Defaults to a random suffix."
  default     = ""
}