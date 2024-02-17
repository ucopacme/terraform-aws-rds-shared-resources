locals {
  create_sql_server_s3_backup_bucket     = var.sql_server_s3_backup_bucket_name != "" ? true : false
  create_sql_server_s3_audit_logs_bucket = var.sql_server_s3_audit_logs_bucket_name != "" ? true : false
  create_sql_server_s3_role              = local.create_sql_server_s3_backup_bucket
  create_sql_server_s3_policy            = local.create_sql_server_s3_backup_bucket
}

