variable "cmk_alias" {
  type        = string
  description = "KMS alias to assign to CMK"
  default     = "alias/ucop/rds"
}

variable "cmk_multi_region" {
  type        = bool
  description = "Create CMK as a multi-region key"
  default     = false
}

variable "cmk_allowed_aws_account_ids" {
  type        = list(string)
  description = "List of other AWS account IDs that will be allowed access to the CMK"
  default     = []
}

variable "sql_server_s3_backup_bucket_name" {
  type        = string
  description = "S3 bucket name for SQL Server native backups and transaction logs for point-in-time recovery"
  default     = ""
}
variable "sql_server_s3_audit_logs_bucket_name" {
  type        = string
  description = "S3 bucket name for SQL Server audit logs"
  default     = ""
}

variable "sql_server_s3_role_name" {
  type        = string
  description = "Name of IAM role used for SQL Server native backups and PITR with S3"
  default     = "rds-sql-server-s3-role"
}

variable "sql_server_s3_policy_name" {
  type        = string
  description = "(Optional) name of IAM policy defining permissions for RDS SQL Server S3 role"
  default     = null
}

variable "kms_key_arns" {
  type        = list(string)
  description = "(Optional) list of other KMS key ARNs that the IAM role should be allowed to access"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "A map of tags to add to all resources"
  default     = {}
}

