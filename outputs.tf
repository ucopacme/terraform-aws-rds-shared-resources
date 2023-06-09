output "rds-sql-server-s3-role_arn" {
  value       = aws_iam_role.rds-sql-server-s3-role.*.arn
  description = "ARN of IAM role used for SQL Server native backups and PITR with S3"
}

output "cmk_key_id" {
  value       = aws_kms_key.cmk.key_id
  description = "KMS key ID of CMK created for RDS storage encryption"
}

