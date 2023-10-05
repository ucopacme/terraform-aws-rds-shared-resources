data "aws_caller_identity" "this" {}

resource "aws_kms_key" "cmk" {
  description              = "CMK for RDS storage encryption"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  multi_region             = var.cmk_multi_region
  policy                   = data.aws_iam_policy_document.cmk.json
  tags                     = var.tags
}

resource "aws_kms_alias" "cmk" {
  name          = var.cmk_alias
  target_key_id = aws_kms_key.cmk.key_id
}

data "aws_iam_policy_document" "cmk" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    resources = ["*"]
    actions   = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.this.account_id}:root"]
    }
  }

  statement {
    sid       = "Allow use of the key"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    principals {
      type        = "AWS"
      identifiers = [for account_id in concat([data.aws_caller_identity.this.account_id], var.cmk_allowed_aws_account_ids) : "arn:aws:iam::${account_id}:root"]
    }
  }

  statement {
    sid       = "Allow attachment of persistent resources"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }

    principals {
      type        = "AWS"
      identifiers = [for account_id in concat([data.aws_caller_identity.this.account_id], var.cmk_allowed_aws_account_ids) : "arn:aws:iam::${account_id}:root"]
    }
  }
}

module "sql_server_s3_backup" {
  count            = local.create_sql_server_s3_backup_bucket ? 1 : 0
  source           = "git::https://git@github.com/ucopacme/terraform-aws-s3-bucket.git"
  bucket           = var.sql_server_s3_backup_bucket_name
  enabled          = true
  object_ownership = "BucketOwnerEnforced"
  policy_enabled   = true
  policy           = data.aws_iam_policy_document.sql_server_s3_backup_bucket_policy.json
  sse_algorithm    = "AES256"
  tags             = var.tags
}

module "sql_server_s3_audit_logs" {
  count            = local.create_sql_server_s3_audit_logs_bucket ? 1 : 0
  source           = "git::https://git@github.com/ucopacme/terraform-aws-s3-bucket.git"
  bucket           = var.sql_server_s3_audit_logs_bucket_name
  enabled          = true
  object_ownership = "BucketOwnerEnforced"
  policy_enabled   = true
  policy           = data.aws_iam_policy_document.sql_server_s3_audit_logs_bucket_policy.json
  sse_algorithm    = "AES256"
  tags             = var.tags
}

# Policy below is from:
# https://aws.amazon.com/blogs/database/achieve-database-level-point-in-time-recovery-on-amazon-rds-for-sql-server-using-access-to-transaction-log-backups-feature
data "aws_iam_policy_document" "sql_server_s3_backup_bucket_base" {
  statement {
    sid       = "Only allow writes to my bucket with bucket owner full control"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}/*"]
    actions   = ["s3:PutObject"]

    condition {
      test     = "StringEquals"
      variable = "aws:sourceAccount"
      values   = [data.aws_caller_identity.this.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    principals {
      type        = "Service"
      identifiers = ["backups.rds.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowSSLRequestsOnly"
    effect = "Deny"

    resources = [
      "arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}",
      "arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}/*"
    ]

    actions = ["s3:*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  statement {
    sid    = "EnforceBucketPolicyViaCode"
    effect = "Deny"

    resources = [
      "arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}"
    ]

    actions = [
      "s3:DeleteBucketPolicy",
      "s3:PutBucketPolicy",
    ]

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalARN"

      values = [
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_rw_*",
      ]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "sql_server_s3_backup_bucket_cross_account" {
  statement {
    sid       = "AllowCrossAccountObjectActions"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}/*"]
    actions   = [
      "s3:GetObject",
      "s3:GetObjectAttributes",
      "s3:ListMultipartUploadParts",
    ]

    principals {
      type        = "AWS"
      identifiers = [for account_id in var.backup_bucket_allowed_aws_account_ids : "arn:aws:iam::${account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCrossAccountBucketActions"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}/*"]
    actions = [
      "s3:GetBucketACL",
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]

    principals {
      type        = "AWS"
      identifiers = [for account_id in var.backup_bucket_allowed_aws_account_ids : "arn:aws:iam::${account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "sql_server_s3_backup_bucket_policy" {
  source_policy_documents = length(var.backup_bucket_allowed_aws_account_ids) == 0 ? [
    data.aws_iam_policy_document.sql_server_s3_backup_bucket_base.json
  ] : [
    data.aws_iam_policy_document.sql_server_s3_backup_bucket_base.json,
    data.aws_iam_policy_document.sql_server_s3_backup_bucket_cross_account.json
  ]
}

data "aws_iam_policy_document" "sql_server_s3_audit_logs_bucket_base" {
  statement {
    sid    = "AllowSSLRequestsOnly"
    effect = "Deny"

    resources = [
      "arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}",
      "arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}/*"
    ]

    actions = ["s3:*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  statement {
    sid    = "EnforceBucketPolicyViaCode"
    effect = "Deny"

    resources = [
      "arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}"
    ]

    actions = [
      "s3:DeleteBucketPolicy",
      "s3:PutBucketPolicy",
    ]

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalARN"

      values = [
        "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_rw_*",
      ]
    }

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "sql_server_s3_audit_logs_bucket_cross_account" {
  statement {
    sid       = "AllowCrossAccountObjectActions"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}/*"]
    actions   = [
      "s3:GetObject",
      "s3:GetObjectAttributes",
      "s3:ListMultipartUploadParts",
    ]

    principals {
      type        = "AWS"
      identifiers = [for account_id in var.audit_logs_bucket_allowed_aws_account_ids : "arn:aws:iam::${account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCrossAccountBucketActions"
    effect    = "Allow"
    resources = ["arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}/*"]
    actions = [
      "s3:GetBucketACL",
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]

    principals {
      type        = "AWS"
      identifiers = [for account_id in var.audit_logs_bucket_allowed_aws_account_ids : "arn:aws:iam::${account_id}:root"]
    }
  }
}

data "aws_iam_policy_document" "sql_server_s3_audit_logs_bucket_policy" {
  source_policy_documents = length(var.audit_logs_bucket_allowed_aws_account_ids) == 0 ? [
    data.aws_iam_policy_document.sql_server_s3_audit_logs_bucket_base.json
  ] : [
    data.aws_iam_policy_document.sql_server_s3_audit_logs_bucket_base.json,
    data.aws_iam_policy_document.sql_server_s3_audit_logs_bucket_cross_account.json
  ]
}

resource "aws_iam_role" "sql_server_s3" {
  count              = local.create_sql_server_s3_role ? 1 : 0
  name               = var.sql_server_s3_role_name
  description        = "Role for RDS SQL Server S3 backup/restore and point-in-time recovery"
  assume_role_policy = data.aws_iam_policy_document.sql_server_s3_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "sql_server_s3_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type = "Service"

      identifiers = [
        "rds.amazonaws.com",
        "ec2.amazonaws.com",
        "enhancedmonitoring.amazonaws.com",
        "monitoring.rds.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy_attachment" "sql_server_s3" {
  count      = local.create_sql_server_s3_role ? 1 : 0
  role       = aws_iam_role.sql_server_s3[0].name
  policy_arn = aws_iam_policy.sql_server_s3[0].arn
}

resource "aws_iam_policy" "sql_server_s3" {
  count       = local.create_sql_server_s3_policy ? 1 : 0
  name        = var.sql_server_s3_policy_name
  description = "Permissions for RDS SQL Server S3 backup/restore and point-in-time recovery"
  policy      = data.aws_iam_policy_document.sql_server_s3_permissions.json
}

data "aws_iam_policy_document" "sql_server_s3_permissions_base" {
  statement {
    sid       = "AllowKMSActions"
    effect    = "Allow"
    resources = concat([aws_kms_key.cmk.arn], var.kms_key_arns)

    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:Encrypt",
      "kms:Decrypt",
    ]
  }

  statement {
    sid       = "AllowBucketActions"
    effect    = "Allow"
    resources = [
      "arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}",
      "arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}",
    ]

    actions = [
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetBucketACL"
    ]
  }

  statement {
    sid       = "AllowBucketObjectActions"
    effect    = "Allow"
    resources = [
      "arn:aws:s3:::${var.sql_server_s3_backup_bucket_name}/*",
      "arn:aws:s3:::${var.sql_server_s3_audit_logs_bucket_name}/*",
    ]

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:GetObjectAttributes",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload",
    ]
  }
  statement {
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "s3:ListAllMyBuckets"
    ]
  }
}

data "aws_iam_policy_document" "sql_server_s3_permissions_read_extra_s3_buckets" {
  statement {
    sid       = "AllowExtraBucketObjectActions"
    effect    = "Allow"
    resources = [for bucket_name in var.read_s3_bucket_names : "arn:aws:s3:::${bucket_name}/*"]
    actions   = [
      "s3:GetObject",
      "s3:GetObjectAttributes",
      "s3:ListMultipartUploadParts",
    ]
  }

  statement {
    sid       = "AllowExtraBucketActions"
    effect    = "Allow"
    resources = [for bucket_name in var.read_s3_bucket_names : "arn:aws:s3:::${bucket_name}"]
    actions = [
      "s3:GetBucketACL",
      "s3:GetBucketLocation",
      "s3:ListBucket",
    ]
  }
}

data "aws_iam_policy_document" "sql_server_s3_permissions" {
  source_policy_documents = length(var.read_s3_bucket_names) == 0 ? [
    data.aws_iam_policy_document.sql_server_s3_permissions_base.json
  ] : [
    data.aws_iam_policy_document.sql_server_s3_permissions_base.json,
    data.aws_iam_policy_document.sql_server_s3_permissions_read_extra_s3_buckets.json
  ]
}

