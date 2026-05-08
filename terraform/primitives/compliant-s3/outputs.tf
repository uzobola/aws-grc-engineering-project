output "bucket_name" {
  description = "Name of the compliant primary S3 bucket."
  value       = aws_s3_bucket.primary.id
}

output "bucket_arn" {
  description = "ARN of the compliant primary S3 bucket."
  value       = aws_s3_bucket.primary.arn
}

output "log_bucket_name" {
  description = "Name of the S3 server access logging bucket."
  value       = aws_s3_bucket.log.id
}

output "log_bucket_arn" {
  description = "ARN of the S3 server access logging bucket."
  value       = aws_s3_bucket.log.arn
}

output "encryption_algorithm" {
  description = "Server-side encryption algorithm used for the primary bucket."
  value = one([
    for rule in aws_s3_bucket_server_side_encryption_configuration.primary.rule :
    rule.apply_server_side_encryption_by_default[0].sse_algorithm
  ])
}

output "compliance_attestation" {
  description = "Machine-readable compliance attestation for the S3 primitive."
  value = {
    encryption_enabled       = true
    encryption_algorithm     = "AES256"
    versioning_enabled       = true
    public_access_blocked    = true
    access_logging_enabled   = true
    managed_by               = "terraform"
    compliance_scope         = "aws-grc-engineering"
    mapped_controls          = ["SC-28", "AU-3", "AU-6", "CM-6", "AC-3"]
  }
}