output "vault_name" {
  description = "S3 bucket name of the evidence vault."
  value       = aws_s3_bucket.vault.id
}

output "vault_arn" {
  description = "ARN of the evidence vault."
  value       = aws_s3_bucket.vault.arn
}

output "object_lock_mode" {
  description = "Default Object Lock retention mode."
  value       = var.lock_mode
}

output "retention_days" {
  description = "Default evidence retention period in days."
  value       = var.retention_days
}

output "evidence_vault_attestation" {
  description = "Machine-readable attestation for the evidence vault."
  value = {
    object_lock_enabled   = true
    versioning_enabled    = true
    encryption_enabled    = true
    encryption_algorithm  = "AES256"
    public_access_blocked = true
    tls_required          = true
    retention_mode        = var.lock_mode
    retention_days        = var.retention_days
  }
}