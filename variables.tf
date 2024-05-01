variable "cmk_enabled" {
  type        = bool
  description = "Whether to create RDS CMK"
  default     = true
}

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
  description = "(Optional) list of other AWS account IDs that will be allowed access to the CMK"
  default     = []
}

variable "sql_server_s3_backup_bucket_name" {
  type        = string
  description = "S3 bucket name for SQL Server native backups and transaction logs for point-in-time recovery"
  default     = ""
}

variable "sql_server_s3_backup_bucket_versioning" {
  type        = string
  description = "versioning on SQL Server backup bucket (Enabled, Suspended, or Disabled)"
  default     = "Disabled"
}

variable "sql_server_s3_audit_logs_bucket_name" {
  type        = string
  description = "S3 bucket name for SQL Server audit logs"
  default     = ""
}

variable "sql_server_s3_audit_logs_bucket_versioning" {
  type        = string
  description = "versioning on SQL Server audit logs bucket (Enabled, Suspended, or Disabled)"
  default     = "Disabled"
}

variable "backup_bucket_allowed_aws_account_ids" {
  type        = list(string)
  description = "(Optional) list of other AWS account IDs that will be allowed read access to the backups bucket"
  default     = []
}

variable "audit_logs_bucket_allowed_aws_account_ids" {
  type        = list(string)
  description = "(Optional) list of other AWS account IDs that will be allowed read access to the audit logs bucket"
  default     = []
}

variable "sql_server_s3_role_name" {
  type        = string
  description = "Name of IAM role used for SQL Server S3 access, including native backups with PITR and audit logging"
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

variable "read_s3_bucket_names" {
  type        = list(string)
  description = "(Optional) list of other S3 bucket names that the IAM role should be allowed to read"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "A map of tags to add to all resources"
  default     = {}
}

