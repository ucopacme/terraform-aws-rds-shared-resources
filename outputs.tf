output "sql_server_s3_role_arn" {
  value       = join("", aws_iam_role.sql_server_s3.*.arn)
  description = "ARN of IAM role used for SQL Server native backups and PITR with S3"
}

output "sql_server_s3_backup_bucket_name" {
  value       = module.sql_server_s3_backup.*.bucket_name
  description = "Bucket Name"
}

output "sql_server_s3_backup_bucket_arn" {
  value       = join("", module.sql_server_s3_backup.*.bucket_arn)
  description = "S3 bucket ARN for SQL Server native backups and transaction logs for point-in-time recovery"
}

output "sql_server_s3_audit_logs_bucket_arn" {
  value       = join("", module.sql_server_s3_audit_logs.*.bucket_arn)
  description = "S3 bucket ARN for SQL Server Audit logs"
}

output "cmk_key_id" {
  value       = aws_kms_key.cmk[0].key_id
  description = "KMS key ID of CMK created for RDS storage encryption"
}

output "cmk_key_arn" {
  value       = aws_kms_key.cmk[0].arn
  description = "KMS key ARN of CMK created for RDS storage encryption"
}
