locals {
  create_sql_server_s3_backup_bucket = var.sql_server_s3_backup_bucket_name != null ? true : false
}

