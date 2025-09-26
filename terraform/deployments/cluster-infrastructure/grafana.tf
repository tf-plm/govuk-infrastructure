locals {
  grafana_db_name         = "grafana-${module.eks.cluster_name}"
  grafana_service_account = "kube-prometheus-stack-grafana"
}

## BEGIN INLINE module grafana_iam_role

# module "grafana_iam_role" {
#   source                        = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
#   version                       = "~> 5.0"
#   create_role                   = true
#   role_name                     = "${local.grafana_service_account}-${module.eks.cluster_name}"
#   role_description              = "Role for Grafana to access AWS data sources. Corresponds to ${local.grafana_service_account} k8s ServiceAccount."
#   provider_url                  = module.eks.oidc_provider
#   role_policy_arns              = [aws_iam_policy.grafana.arn]
#   oidc_fully_qualified_subjects = ["system:serviceaccount:${local.monitoring_namespace}:${local.grafana_service_account}"]
# }

# INPUTS module grafana_iam_role
locals {
  modin_grafana_iam_role_create_role = true
  modin_grafana_iam_role_provider_url = module.eks.oidc_provider
  modin_grafana_iam_role_provider_urls = []
  modin_grafana_iam_role_aws_account_id = ""
  modin_grafana_iam_role_tags = {}
  modin_grafana_iam_role_role_name = "${local.grafana_service_account}-${module.eks.cluster_name}"
  modin_grafana_iam_role_role_name_prefix = null
  modin_grafana_iam_role_role_description = "Role for Grafana to access AWS data sources. Corresponds to ${local.grafana_service_account} k8s ServiceAccount."
  modin_grafana_iam_role_role_path = "/"
  modin_grafana_iam_role_role_permissions_boundary_arn = ""
  modin_grafana_iam_role_max_session_duration = 3600
  modin_grafana_iam_role_role_policy_arns = [aws_iam_policy.grafana.arn]
  modin_grafana_iam_role_number_of_role_policy_arns = null
  modin_grafana_iam_role_inline_policy_statements = []
  modin_grafana_iam_role_oidc_fully_qualified_subjects = ["system:serviceaccount:${local.monitoring_namespace}:${local.grafana_service_account}"]
  modin_grafana_iam_role_oidc_subjects_with_wildcards = []
  modin_grafana_iam_role_oidc_fully_qualified_audiences = []
  modin_grafana_iam_role_force_detach_policies = false
  modin_grafana_iam_role_allow_self_assume_role = false
  modin_grafana_iam_role_provider_trust_policy_conditions = []
}

## OUTPUTS module grafana_iam_role
locals {
  modout_grafana_iam_role_iam_role_arn =  try(aws_iam_role.mod_grafana_iam_role_this[0].arn, "")
  modout_grafana_iam_role_iam_role_name = try(aws_iam_role.mod_grafana_iam_role_this[0].name, "")
  modout_grafana_iam_role_iam_role_path = try(aws_iam_role.mod_grafana_iam_role_this[0].path, "")
  modout_grafana_iam_role_iam_role_unique_id = try(aws_iam_role.mod_grafana_iam_role_this[0].unique_id, "")
}

## RESOURCES

locals {
  mod_grafana_iam_role_aws_account_id = local.modin_grafana_iam_role_aws_account_id != "" ? local.modin_grafana_iam_role_aws_account_id : data.aws_caller_identity.mod_grafana_iam_role_current.account_id
  mod_grafana_iam_role_partition      = data.aws_partition.mod_grafana_iam_role_current.partition
  # clean URLs of https:// prefix
  mod_grafana_iam_role_urls = [
    for url in compact(distinct(concat(local.modin_grafana_iam_role_provider_urls, [local.modin_grafana_iam_role_provider_url]))) :
    replace(url, "https://", "")
  ]
  mod_grafana_iam_role_number_of_role_policy_arns = coalesce(local.modin_grafana_iam_role_number_of_role_policy_arns, length(local.modin_grafana_iam_role_role_policy_arns))
  mod_grafana_iam_role_role_name_condition        = local.modin_grafana_iam_role_role_name != null ? local.modin_grafana_iam_role_role_name : "${local.modin_grafana_iam_role_role_name_prefix}*"
}

data "aws_caller_identity" "mod_grafana_iam_role_current" {}
data "aws_partition" "mod_grafana_iam_role_current" {}

data "aws_iam_policy_document" "mod_grafana_iam_role_assume_role_with_oidc" {
  count = local.modin_grafana_iam_role_create_role ? 1 : 0

  dynamic "statement" {
    # https://aws.amazon.com/blogs/security/announcing-an-update-to-iam-role-trust-policy-behavior/
    for_each = local.modin_grafana_iam_role_allow_self_assume_role ? [1] : []

    content {
      sid     = "ExplicitSelfRoleAssumption"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
        values   = ["arn:${local.mod_grafana_iam_role_partition}:iam::${data.aws_caller_identity.mod_grafana_iam_role_current.account_id}:role${local.modin_grafana_iam_role_role_path}${local.mod_grafana_iam_role_role_name_condition}"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.mod_grafana_iam_role_urls

    content {
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]

      principals {
        type = "Federated"

        identifiers = ["arn:${data.aws_partition.mod_grafana_iam_role_current.partition}:iam::${local.mod_grafana_iam_role_aws_account_id}:oidc-provider/${statement.value}"]
      }

      dynamic "condition" {
        for_each = length(local.modin_grafana_iam_role_oidc_fully_qualified_subjects) > 0 ? local.mod_grafana_iam_role_urls : []

        content {
          test     = "StringEquals"
          variable = "${statement.value}:sub"
          values   = local.modin_grafana_iam_role_oidc_fully_qualified_subjects
        }
      }

      dynamic "condition" {
        for_each = length(local.modin_grafana_iam_role_oidc_subjects_with_wildcards) > 0 ? local.mod_grafana_iam_role_urls : []

        content {
          test     = "StringLike"
          variable = "${statement.value}:sub"
          values   = local.modin_grafana_iam_role_oidc_subjects_with_wildcards
        }
      }

      dynamic "condition" {
        for_each = length(local.modin_grafana_iam_role_oidc_fully_qualified_audiences) > 0 ? local.mod_grafana_iam_role_urls : []

        content {
          test     = "StringLike"
          variable = "${statement.value}:aud"
          values   = local.modin_grafana_iam_role_oidc_fully_qualified_audiences
        }
      }

      dynamic "condition" {
        for_each = local.modin_grafana_iam_role_provider_trust_policy_conditions

        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }
    }
  }
}

resource "aws_iam_role" "mod_grafana_iam_role_this" {
  count = local.modin_grafana_iam_role_create_role ? 1 : 0

  name                 = local.modin_grafana_iam_role_role_name
  name_prefix          = local.modin_grafana_iam_role_role_name_prefix
  description          = local.modin_grafana_iam_role_role_description
  path                 = local.modin_grafana_iam_role_role_path
  max_session_duration = local.modin_grafana_iam_role_max_session_duration

  force_detach_policies = local.modin_grafana_iam_role_force_detach_policies
  permissions_boundary  = local.modin_grafana_iam_role_role_permissions_boundary_arn

  assume_role_policy = data.aws_iam_policy_document.mod_grafana_iam_role_assume_role_with_oidc[0].json

  tags = local.modin_grafana_iam_role_tags
}

resource "aws_iam_role_policy_attachment" "mod_grafana_iam_role_custom" {
  count = local.modin_grafana_iam_role_create_role ? local.mod_grafana_iam_role_number_of_role_policy_arns : 0

  role       = aws_iam_role.mod_grafana_iam_role_this[0].name
  policy_arn = local.modin_grafana_iam_role_role_policy_arns[count.index]
}

###############################
# IAM Role Inline policy
###############################

locals {
  mod_grafana_iam_role_create_iam_role_inline_policy = local.modin_grafana_iam_role_create_role && length(local.modin_grafana_iam_role_inline_policy_statements) > 0
}

data "aws_iam_policy_document" "mod_grafana_iam_role_inline" {
  count = local.mod_grafana_iam_role_create_iam_role_inline_policy ? 1 : 0

  dynamic "statement" {
    for_each = local.modin_grafana_iam_role_inline_policy_statements

    content {
      sid           = try(statement.value.sid, null)
      actions       = try(statement.value.actions, null)
      not_actions   = try(statement.value.not_actions, null)
      effect        = try(statement.value.effect, null)
      resources     = try(statement.value.resources, null)
      not_resources = try(statement.value.not_resources, null)

      dynamic "principals" {
        for_each = try(statement.value.principals, [])

        content {
          type        = principals.value.type
          identifiers = principals.value.identifiers
        }
      }

      dynamic "not_principals" {
        for_each = try(statement.value.not_principals, [])

        content {
          type        = not_principals.value.type
          identifiers = not_principals.value.identifiers
        }
      }

      dynamic "condition" {
        for_each = try(statement.value.conditions, [])

        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }
    }
  }
}

resource "aws_iam_role_policy" "mod_grafana_iam_role_inline" {
  count = local.mod_grafana_iam_role_create_iam_role_inline_policy ? 1 : 0

  role        = aws_iam_role.mod_grafana_iam_role_this[0].name
  name_prefix = "${local.modin_grafana_iam_role_role_name}_inline_"
  policy      = data.aws_iam_policy_document.mod_grafana_iam_role_inline[0].json
}

## END INLINED module grafana_iam_role

data "aws_iam_policy_document" "grafana" {
  statement {
    sid    = "AllowReadingMetricsFromCloudWatch"
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListMetrics",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetInsightRuleReport"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowReadingLogsFromCloudWatch"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:GetLogGroupFields",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:GetQueryResults",
      "logs:GetLogEvents"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowReadingTagsInstancesRegionsFromEC2"
    effect = "Allow"
    actions = [
      "ec2:DescribeTags",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowReadingResourcesForTags"
    effect = "Allow"
    actions = [
      "tag:GetResources"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "grafana" {
  name        = "grafana-${module.eks.cluster_name}"
  description = "Allows Grafana to access AWS data sources."

  # Values was obtained from
  # https://grafana.com/docs/grafana/latest/datasources/aws-cloudwatch/ (v8.4).
  policy = data.aws_iam_policy_document.grafana.json
}

data "aws_rds_engine_version" "postgresql" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  engine  = "aurora-postgresql"
  version = "16"
  latest  = true
}

resource "random_password" "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  length  = 20
  special = false

  lifecycle { ignore_changes = [special] }
}

locals {
  rds_subnet_ids     = compact([for name, id in var.tfe_outputs_vpc_nonsensitive_values.private_subnet_ids : startswith(name, "rds_") ? id : ""])
  grafana_subnet_ids = startswith(var.govuk_environment, "eph-") ? [for sn in aws_subnet.eks_private : sn.id] : local.rds_subnet_ids
}

# module "grafana_db" {
#   count = startswith(var.govuk_environment, "eph-") ? 0 : 1

#   source  = "terraform-aws-modules/rds-aurora/aws"
#   version = "~> 9.0"

#   name              = local.grafana_db_name
#   database_name     = "grafana"
#   engine            = "aurora-postgresql"
#   engine_mode       = "provisioned"
#   engine_version    = data.aws_rds_engine_version.postgresql[count.index].version
#   storage_encrypted = true

#   allow_major_version_upgrade = true

#   vpc_id                 = var.tfe_outputs_vpc_nonsensitive_values.id
#   subnets                = local.grafana_subnet_ids
#   create_db_subnet_group = true
#   create_security_group  = true
#   security_group_rules = {
#     from_cluster = { source_security_group_id = module.eks.cluster_primary_security_group_id }
#   }
#   manage_master_user_password = false
#   master_username             = "root"
#   master_password             = random_password.grafana_db[count.index].result

#   serverlessv2_scaling_configuration = {
#     max_capacity             = 256
#     min_capacity             = 0
#     seconds_until_auto_pause = 300
#   }

#   instance_class = "db.serverless"
#   instances = {
#     one = {
#       identifier = "${local.grafana_db_name}-instance-1"
#     }
#   }

#   apply_immediately            = var.rds_apply_immediately
#   backup_retention_period      = var.rds_backup_retention_period
#   skip_final_snapshot          = var.rds_skip_final_snapshot
#   final_snapshot_identifier    = "${local.grafana_db_name}-final"
#   preferred_backup_window      = "02:00-03:00"
#   preferred_maintenance_window = "sun:04:00-sun:05:00"
# }

## BEGIN INLINE module grafana_db

## INPUTS

locals {
  modin_grafana_db_create = true

  modin_grafana_db_name = local.grafana_db_name

  modin_grafana_db_tags = {}

  ################################################################################
  # DB Subnet Group
  ################################################################################

  modin_grafana_db_create_db_subnet_group = true

  modin_grafana_db_db_subnet_group_name = ""

  modin_grafana_db_subnets = local.grafana_subnet_ids

  ################################################################################
  # Cluster
  ################################################################################

  modin_grafana_db_is_primary_cluster = true

  modin_grafana_db_cluster_use_name_prefix = false

  modin_grafana_db_allocated_storage = null

  modin_grafana_db_allow_major_version_upgrade = true

  modin_grafana_db_apply_immediately = var.rds_apply_immediately

  modin_grafana_db_availability_zones = null

  modin_grafana_db_backup_retention_period = var.rds_backup_retention_period

  modin_grafana_db_backtrack_window = null

  modin_grafana_db_cluster_ca_cert_identifier = null

  modin_grafana_db_cluster_members = null

  modin_grafana_db_cluster_scalability_type = null

  modin_grafana_db_cluster_performance_insights_enabled = null

  modin_grafana_db_cluster_performance_insights_kms_key_id = null

  modin_grafana_db_cluster_performance_insights_retention_period = null

  modin_grafana_db_cluster_monitoring_interval = 0

  modin_grafana_db_copy_tags_to_snapshot = null

  modin_grafana_db_database_insights_mode = null

  modin_grafana_db_database_name = "grafana"

  modin_grafana_db_db_cluster_instance_class = null

  modin_grafana_db_db_cluster_db_instance_parameter_group_name = null

  modin_grafana_db_delete_automated_backups = null

  modin_grafana_db_deletion_protection = null

  modin_grafana_db_enable_global_write_forwarding = null

  modin_grafana_db_enable_local_write_forwarding = null

  modin_grafana_db_enabled_cloudwatch_logs_exports = []

  modin_grafana_db_enable_http_endpoint = null

  modin_grafana_db_engine = "aurora-postgresql"

  modin_grafana_db_engine_mode = "provisioned"

  modin_grafana_db_engine_version = data.aws_rds_engine_version.postgresql[0].version

  modin_grafana_db_engine_lifecycle_support = null

  modin_grafana_db_final_snapshot_identifier = "${local.grafana_db_name}-final"

  modin_grafana_db_global_cluster_identifier = null

  modin_grafana_db_iam_database_authentication_enabled = null

  modin_grafana_db_domain = null

  modin_grafana_db_domain_iam_role_name = null

  modin_grafana_db_iops = null

  modin_grafana_db_kms_key_id = null

  modin_grafana_db_manage_master_user_password = false

  modin_grafana_db_master_user_secret_kms_key_id = null

  modin_grafana_db_master_password = random_password.grafana_db[0].result

  modin_grafana_db_master_username = "root"

  modin_grafana_db_network_type = null

  modin_grafana_db_port = null

  modin_grafana_db_preferred_backup_window = "02:00-03:00"

  modin_grafana_db_preferred_maintenance_window = "sun:04:00-sun:05:00"

  modin_grafana_db_replication_source_identifier = null

  modin_grafana_db_restore_to_point_in_time = {}

  modin_grafana_db_s3_import = {}

  modin_grafana_db_scaling_configuration = {}

  modin_grafana_db_serverlessv2_scaling_configuration = {
    max_capacity             = 256
    min_capacity             = 0
    seconds_until_auto_pause = 300
  }

  modin_grafana_db_skip_final_snapshot = var.rds_skip_final_snapshot

  modin_grafana_db_snapshot_identifier = null

  modin_grafana_db_source_region = null

  modin_grafana_db_storage_encrypted = true

  modin_grafana_db_storage_type = null

  modin_grafana_db_cluster_tags = {}

  modin_grafana_db_vpc_security_group_ids = []

  modin_grafana_db_cluster_timeouts = {}

  ################################################################################
  # Cluster Instance(s)
  ################################################################################

  modin_grafana_db_instances = {
    one = {
      identifier = "${local.grafana_db_name}-instance-1"
    }
  }

  modin_grafana_db_auto_minor_version_upgrade = null

  modin_grafana_db_ca_cert_identifier = null

  modin_grafana_db_db_parameter_group_name = null

  modin_grafana_db_instances_use_identifier_prefix = false

  modin_grafana_db_instance_class = "db.serverless"

  modin_grafana_db_monitoring_interval = 0

  modin_grafana_db_performance_insights_enabled = null

  modin_grafana_db_performance_insights_kms_key_id = null

  modin_grafana_db_performance_insights_retention_period = null

  modin_grafana_db_publicly_accessible = null

  modin_grafana_db_instance_timeouts = {}

  ################################################################################
  # Cluster Endpoint(s)
  ################################################################################

  modin_grafana_db_endpoints = {}

  ################################################################################
  # Cluster IAM Roles
  ################################################################################

  modin_grafana_db_iam_roles = {}

  ################################################################################
  # Enhanced Monitoring
  ################################################################################

  modin_grafana_db_create_monitoring_role = true

  modin_grafana_db_monitoring_role_arn = ""

  modin_grafana_db_iam_role_name = null

  modin_grafana_db_iam_role_use_name_prefix = false

  modin_grafana_db_iam_role_description = null

  modin_grafana_db_iam_role_path = null

  modin_grafana_db_iam_role_managed_policy_arns = null

  modin_grafana_db_iam_role_permissions_boundary = null

  modin_grafana_db_iam_role_force_detach_policies = null

  modin_grafana_db_iam_role_max_session_duration = null

  ################################################################################
  # Autoscaling
  ################################################################################

  modin_grafana_db_autoscaling_enabled = false

  modin_grafana_db_autoscaling_max_capacity = 2

  modin_grafana_db_autoscaling_min_capacity = 0

  modin_grafana_db_autoscaling_policy_name = "target-metric"

  modin_grafana_db_predefined_metric_type = "RDSReaderAverageCPUUtilization"

  modin_grafana_db_autoscaling_scale_in_cooldown = 300

  modin_grafana_db_autoscaling_scale_out_cooldown = 300

  modin_grafana_db_autoscaling_target_cpu = 70

  modin_grafana_db_autoscaling_target_connections = 700

  ################################################################################
  # Security Group
  ################################################################################

  modin_grafana_db_create_security_group = true

  modin_grafana_db_security_group_name = ""

  modin_grafana_db_security_group_use_name_prefix = true

  modin_grafana_db_security_group_description = null

  modin_grafana_db_vpc_id = var.tfe_outputs_vpc_nonsensitive_values.id

  modin_grafana_db_security_group_rules = {
    from_cluster = { source_security_group_id = module.eks.cluster_primary_security_group_id }
  }

  modin_grafana_db_security_group_tags = {}

  ################################################################################
  # Cluster Parameter Group
  ################################################################################

  modin_grafana_db_create_db_cluster_parameter_group = false

  modin_grafana_db_db_cluster_parameter_group_name = null

  modin_grafana_db_db_cluster_parameter_group_use_name_prefix = true

  modin_grafana_db_db_cluster_parameter_group_description = null

  modin_grafana_db_db_cluster_parameter_group_family = ""

  modin_grafana_db_db_cluster_parameter_group_parameters = []

  ################################################################################
  # DB Parameter Group
  ################################################################################

  modin_grafana_db_create_db_parameter_group = false

  modin_grafana_db_db_parameter_group_use_name_prefix = true

  modin_grafana_db_db_parameter_group_description = null

  modin_grafana_db_db_parameter_group_family = ""

  modin_grafana_db_db_parameter_group_parameters = []

  modin_grafana_db_putin_khuylo = true

  ################################################################################
  # CloudWatch Log Group
  ################################################################################

  modin_grafana_db_create_cloudwatch_log_group = false

  modin_grafana_db_cloudwatch_log_group_retention_in_days = 7

  modin_grafana_db_cloudwatch_log_group_kms_key_id = null

  modin_grafana_db_cloudwatch_log_group_skip_destroy = null

  modin_grafana_db_cloudwatch_log_group_class = null

  modin_grafana_db_cloudwatch_log_group_tags = {}

  ################################################################################
  # Cluster Activity Stream
  ################################################################################

  modin_grafana_db_create_db_cluster_activity_stream = false

  modin_grafana_db_db_cluster_activity_stream_mode = "sync"

  modin_grafana_db_db_cluster_activity_stream_kms_key_id = "randomid"

  modin_grafana_db_engine_native_audit_fields_included = false

  ################################################################################
  # Managed Secret Rotation
  ################################################################################

  modin_grafana_db_manage_master_user_password_rotation = false

  modin_grafana_db_master_user_password_rotate_immediately = null

  modin_grafana_db_master_user_password_rotation_automatically_after_days = 3

  modin_grafana_db_master_user_password_rotation_duration = null

  modin_grafana_db_master_user_password_rotation_schedule_expression = null

  ################################################################################
  # RDS Shard Group
  ################################################################################

  modin_grafana_db_create_shard_group = false

  modin_grafana_db_compute_redundancy = null

  modin_grafana_db_db_shard_group_identifier = "shard-group-id"

  modin_grafana_db_max_acu = 3

  modin_grafana_db_min_acu = null

  modin_grafana_db_shard_group_tags = {}

  modin_grafana_db_shard_group_timeouts = {}
}

## OUTPUTS

locals {
  ################################################################################
  # DB Subnet Group
  ################################################################################

  modout_grafana_db_db_subnet_group_name = local.mod_grafana_db_db_subnet_group_name

  ################################################################################
  # Cluster
  ################################################################################

  modout_grafana_db_cluster_arn = try(aws_rds_cluster.mod_grafana_db_this[0].arn, null)

  modout_grafana_db_cluster_id = try(aws_rds_cluster.mod_grafana_db_this[0].id, null)

  modout_grafana_db_cluster_resource_id = try(aws_rds_cluster.mod_grafana_db_this[0].cluster_resource_id, null)

  modout_grafana_db_cluster_members = try(aws_rds_cluster.mod_grafana_db_this[0].cluster_members, null)

  modout_grafana_db_cluster_endpoint = try(aws_rds_cluster.mod_grafana_db_this[0].endpoint, null)

  modout_grafana_db_cluster_reader_endpoint = try(aws_rds_cluster.mod_grafana_db_this[0].reader_endpoint, null)

  modout_grafana_db_cluster_engine_version_actual = try(aws_rds_cluster.mod_grafana_db_this[0].engine_version_actual, null)

  # database_name is not set on `aws_rds_cluster` resource if it was not specified, so can't be used in output
  modout_grafana_db_cluster_database_name = local.modin_grafana_db_database_name

  modout_grafana_db_cluster_port = try(aws_rds_cluster.mod_grafana_db_this[0].port, null)

  modout_grafana_db_cluster_master_password = try(aws_rds_cluster.mod_grafana_db_this[0].master_password, null)

  modout_grafana_db_cluster_master_username = try(aws_rds_cluster.mod_grafana_db_this[0].master_username, null)

  modout_grafana_db_cluster_master_user_secret = try(aws_rds_cluster.mod_grafana_db_this[0].master_user_secret, null)

  modout_grafana_db_cluster_hosted_zone_id = try(aws_rds_cluster.mod_grafana_db_this[0].hosted_zone_id, null)

  modout_grafana_db_cluster_ca_certificate_identifier = try(aws_rds_cluster.mod_grafana_db_this[0].ca_certificate_identifier, null)

  modout_grafana_db_cluster_ca_certificate_valid_till = try(aws_rds_cluster.mod_grafana_db_this[0].ca_certificate_valid_till, null)

  ################################################################################
  # Cluster Instance(s)
  ################################################################################

  modout_grafana_db_cluster_instances = aws_rds_cluster_instance.mod_grafana_db_this

  ################################################################################
  # Cluster Endpoint(s)
  ################################################################################

  modout_grafana_db_additional_cluster_endpoints = aws_rds_cluster_endpoint.mod_grafana_db_this

  ################################################################################
  # Cluster IAM Roles
  ################################################################################

  modout_grafana_db_cluster_role_associations = aws_rds_cluster_role_association.mod_grafana_db_this

  ################################################################################
  # Enhanced Monitoring
  ################################################################################

  modout_grafana_db_enhanced_monitoring_iam_role_name = try(aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].name, null)

  modout_grafana_db_enhanced_monitoring_iam_role_arn = try(aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].arn, null)

  modout_grafana_db_enhanced_monitoring_iam_role_unique_id = try(aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].unique_id, null)

  ################################################################################
  # Security Group
  ################################################################################

  modout_grafana_db_security_group_id = try(aws_security_group.mod_grafana_db_this[0].id, null)

  ################################################################################
  # Cluster Parameter Group
  ################################################################################

  modout_grafana_db_db_cluster_parameter_group_arn = try(aws_rds_cluster_parameter_group.mod_grafana_db_this[0].arn, null)

  modout_grafana_db_db_cluster_parameter_group_id = try(aws_rds_cluster_parameter_group.mod_grafana_db_this[0].id, null)

  ################################################################################
  # DB Parameter Group
  ################################################################################

  modout_grafana_db_db_parameter_group_arn = try(aws_db_parameter_group.mod_grafana_db_this[0].arn, null)

  modout_grafana_db_db_parameter_group_id = try(aws_db_parameter_group.mod_grafana_db_this[0].id, null)

  ################################################################################
  # CloudWatch Log Group
  ################################################################################

  modout_grafana_db_db_cluster_cloudwatch_log_groups = aws_cloudwatch_log_group.mod_grafana_db_this

  ################################################################################
  # Cluster Activity Stream
  ################################################################################

  modout_grafana_db_db_cluster_activity_stream_kinesis_stream_name = try(aws_rds_cluster_activity_stream.mod_grafana_db_this[0].kinesis_stream_name, null)

  ################################################################################
  # Managed Secret Rotation
  ################################################################################

  modout_grafana_db_db_cluster_secretsmanager_secret_rotation_enabled = try(aws_secretsmanager_secret_rotation.mod_grafana_db_this[0].rotation_enabled, null)

  ################################################################################
  # RDS Shard Group
  ################################################################################

  modout_grafana_db_db_shard_group_arn = try(aws_rds_shard_group.mod_grafana_db_this[0].arn, null)

  modout_grafana_db_db_shard_group_resource_id = try(aws_rds_shard_group.mod_grafana_db_this[0].db_shard_group_resource_id, null)

  modout_grafana_db_db_shard_group_endpoint = try(aws_rds_shard_group.mod_grafana_db_this[0].endpoint, null)
}

## RESOURCES

data "aws_partition" "mod_grafana_db_current" {}

locals {
  mod_grafana_db_create = local.modin_grafana_db_create && local.modin_grafana_db_putin_khuylo

  mod_grafana_db_port = coalesce(local.modin_grafana_db_port, (local.modin_grafana_db_engine == "aurora-postgresql" || local.modin_grafana_db_engine == "postgres" ? 5432 : 3306))

  mod_grafana_db_internal_db_subnet_group_name = try(coalesce(local.modin_grafana_db_db_subnet_group_name, local.modin_grafana_db_name), "")
  mod_grafana_db_db_subnet_group_name          = local.modin_grafana_db_create_db_subnet_group ? try(aws_db_subnet_group.mod_grafana_db_this[0].name, null) : local.mod_grafana_db_internal_db_subnet_group_name

  mod_grafana_db_security_group_name = try(coalesce(local.modin_grafana_db_security_group_name, local.modin_grafana_db_name), "")

  mod_grafana_db_cluster_parameter_group_name = try(coalesce(local.modin_grafana_db_db_cluster_parameter_group_name, local.modin_grafana_db_name), null)
  mod_grafana_db_db_parameter_group_name      = try(coalesce(local.modin_grafana_db_db_parameter_group_name, local.modin_grafana_db_name), null)

  mod_grafana_db_backtrack_window = (local.modin_grafana_db_engine == "aurora-mysql" || local.modin_grafana_db_engine == "aurora") && local.modin_grafana_db_engine_mode != "serverless" ? local.modin_grafana_db_backtrack_window : 0

  mod_grafana_db_is_serverless = local.modin_grafana_db_engine_mode == "serverless"
}

################################################################################
# DB Subnet Group
################################################################################

resource "aws_db_subnet_group" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_db_subnet_group ? 1 : 0

  name        = local.mod_grafana_db_internal_db_subnet_group_name
  description = "For Aurora cluster ${local.modin_grafana_db_name}"
  subnet_ids  = local.modin_grafana_db_subnets

  tags = local.modin_grafana_db_tags
}

################################################################################
# Cluster
################################################################################

resource "aws_rds_cluster" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create ? 1 : 0

  allocated_storage                   = local.modin_grafana_db_allocated_storage
  allow_major_version_upgrade         = local.modin_grafana_db_allow_major_version_upgrade
  apply_immediately                   = local.modin_grafana_db_apply_immediately
  availability_zones                  = local.modin_grafana_db_availability_zones
  backup_retention_period             = local.modin_grafana_db_backup_retention_period
  backtrack_window                    = local.mod_grafana_db_backtrack_window
  ca_certificate_identifier           = local.modin_grafana_db_cluster_ca_cert_identifier
  cluster_identifier                  = local.modin_grafana_db_cluster_use_name_prefix ? null : local.modin_grafana_db_name
  cluster_identifier_prefix           = local.modin_grafana_db_cluster_use_name_prefix ? "${local.modin_grafana_db_name}-" : null
  cluster_members                     = local.modin_grafana_db_cluster_members
  cluster_scalability_type            = local.modin_grafana_db_cluster_scalability_type
  copy_tags_to_snapshot               = local.modin_grafana_db_copy_tags_to_snapshot
  database_insights_mode              = local.modin_grafana_db_database_insights_mode
  database_name                       = local.modin_grafana_db_is_primary_cluster ? local.modin_grafana_db_database_name : null
  db_cluster_instance_class           = local.modin_grafana_db_db_cluster_instance_class
  db_cluster_parameter_group_name     = local.modin_grafana_db_create_db_cluster_parameter_group ? aws_rds_cluster_parameter_group.mod_grafana_db_this[0].id : local.modin_grafana_db_db_cluster_parameter_group_name
  db_instance_parameter_group_name    = local.modin_grafana_db_allow_major_version_upgrade ? local.modin_grafana_db_db_cluster_db_instance_parameter_group_name : null
  db_subnet_group_name                = local.mod_grafana_db_db_subnet_group_name
  delete_automated_backups            = local.modin_grafana_db_delete_automated_backups
  deletion_protection                 = local.modin_grafana_db_deletion_protection
  enable_global_write_forwarding      = local.modin_grafana_db_enable_global_write_forwarding
  enable_local_write_forwarding       = local.modin_grafana_db_enable_local_write_forwarding
  enabled_cloudwatch_logs_exports     = local.modin_grafana_db_enabled_cloudwatch_logs_exports
  enable_http_endpoint                = local.modin_grafana_db_enable_http_endpoint
  engine                              = local.modin_grafana_db_engine
  engine_mode                         = local.modin_grafana_db_cluster_scalability_type == "limitless" ? "" : local.modin_grafana_db_engine_mode
  engine_version                      = local.modin_grafana_db_engine_version
  engine_lifecycle_support            = local.modin_grafana_db_engine_lifecycle_support
  final_snapshot_identifier           = local.modin_grafana_db_final_snapshot_identifier
  global_cluster_identifier           = local.modin_grafana_db_global_cluster_identifier
  domain                              = local.modin_grafana_db_domain
  domain_iam_role_name                = local.modin_grafana_db_domain_iam_role_name
  iam_database_authentication_enabled = local.modin_grafana_db_iam_database_authentication_enabled
  # iam_roles has been removed from this resource and instead will be used with aws_rds_cluster_role_association below to avoid conflicts per docs
  iops                                  = local.modin_grafana_db_iops
  kms_key_id                            = local.modin_grafana_db_kms_key_id
  manage_master_user_password           = local.modin_grafana_db_global_cluster_identifier == null && local.modin_grafana_db_manage_master_user_password ? local.modin_grafana_db_manage_master_user_password : null
  master_user_secret_kms_key_id         = local.modin_grafana_db_global_cluster_identifier == null && local.modin_grafana_db_manage_master_user_password ? local.modin_grafana_db_master_user_secret_kms_key_id : null
  master_password                       = local.modin_grafana_db_is_primary_cluster && !local.modin_grafana_db_manage_master_user_password ? local.modin_grafana_db_master_password : null
  master_username                       = local.modin_grafana_db_is_primary_cluster ? local.modin_grafana_db_master_username : null
  monitoring_interval                   = local.modin_grafana_db_cluster_monitoring_interval
  monitoring_role_arn                   = local.modin_grafana_db_create_monitoring_role && local.modin_grafana_db_cluster_monitoring_interval > 0 ? try(aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].arn, null) : local.modin_grafana_db_monitoring_role_arn
  network_type                          = local.modin_grafana_db_network_type
  performance_insights_enabled          = local.modin_grafana_db_cluster_performance_insights_enabled
  performance_insights_kms_key_id       = local.modin_grafana_db_cluster_performance_insights_kms_key_id
  performance_insights_retention_period = local.modin_grafana_db_cluster_performance_insights_retention_period
  port                                  = local.mod_grafana_db_port
  preferred_backup_window               = local.mod_grafana_db_is_serverless ? null : local.modin_grafana_db_preferred_backup_window
  preferred_maintenance_window          = local.modin_grafana_db_preferred_maintenance_window
  replication_source_identifier         = local.modin_grafana_db_replication_source_identifier

  dynamic "restore_to_point_in_time" {
    for_each = length(local.modin_grafana_db_restore_to_point_in_time) > 0 ? [local.modin_grafana_db_restore_to_point_in_time] : []

    content {
      restore_to_time            = try(restore_to_point_in_time.value.restore_to_time, null)
      restore_type               = try(restore_to_point_in_time.value.restore_type, null)
      source_cluster_identifier  = try(restore_to_point_in_time.value.source_cluster_identifier, null)
      source_cluster_resource_id = try(restore_to_point_in_time.value.source_cluster_resource_id, null)
      use_latest_restorable_time = try(restore_to_point_in_time.value.use_latest_restorable_time, null)
    }
  }

  dynamic "s3_import" {
    for_each = length(local.modin_grafana_db_s3_import) > 0 && !local.mod_grafana_db_is_serverless ? [local.modin_grafana_db_s3_import] : []

    content {
      bucket_name           = s3_import.value.bucket_name
      bucket_prefix         = try(s3_import.value.bucket_prefix, null)
      ingestion_role        = s3_import.value.ingestion_role
      source_engine         = "mysql"
      source_engine_version = s3_import.value.source_engine_version
    }
  }

  dynamic "scaling_configuration" {
    for_each = length(local.modin_grafana_db_scaling_configuration) > 0 && local.mod_grafana_db_is_serverless ? [local.modin_grafana_db_scaling_configuration] : []

    content {
      auto_pause               = try(scaling_configuration.value.auto_pause, null)
      max_capacity             = try(scaling_configuration.value.max_capacity, null)
      min_capacity             = try(scaling_configuration.value.min_capacity, null)
      seconds_until_auto_pause = try(scaling_configuration.value.seconds_until_auto_pause, null)
      seconds_before_timeout   = try(scaling_configuration.value.seconds_before_timeout, null)
      timeout_action           = try(scaling_configuration.value.timeout_action, null)
    }
  }

  dynamic "serverlessv2_scaling_configuration" {
    for_each = length(local.modin_grafana_db_serverlessv2_scaling_configuration) > 0 && local.modin_grafana_db_engine_mode == "provisioned" ? [local.modin_grafana_db_serverlessv2_scaling_configuration] : []

    content {
      max_capacity             = serverlessv2_scaling_configuration.value.max_capacity
      min_capacity             = serverlessv2_scaling_configuration.value.min_capacity
      seconds_until_auto_pause = try(serverlessv2_scaling_configuration.value.seconds_until_auto_pause, null)
    }
  }

  skip_final_snapshot    = local.modin_grafana_db_skip_final_snapshot
  snapshot_identifier    = local.modin_grafana_db_snapshot_identifier
  source_region          = local.modin_grafana_db_source_region
  storage_encrypted      = local.modin_grafana_db_storage_encrypted
  storage_type           = local.modin_grafana_db_storage_type
  tags                   = merge(local.modin_grafana_db_tags, local.modin_grafana_db_cluster_tags)
  vpc_security_group_ids = compact(concat([try(aws_security_group.mod_grafana_db_this[0].id, "")], local.modin_grafana_db_vpc_security_group_ids))

  timeouts {
    create = try(local.modin_grafana_db_cluster_timeouts.create, null)
    update = try(local.modin_grafana_db_cluster_timeouts.update, null)
    delete = try(local.modin_grafana_db_cluster_timeouts.delete, null)
  }

  lifecycle {
    ignore_changes = [
      # See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#replication_source_identifier
      # Since this is used either in read-replica clusters or global clusters, this should be acceptable to specify
      replication_source_identifier,
      # See docs here https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_global_cluster#new-global-cluster-from-existing-db-cluster
      global_cluster_identifier,
      snapshot_identifier,
    ]
  }

  depends_on = [aws_cloudwatch_log_group.mod_grafana_db_this]
}

################################################################################
# Cluster Instance(s)
################################################################################

resource "aws_rds_cluster_instance" "mod_grafana_db_this" {
  for_each = { for k, v in local.modin_grafana_db_instances : k => v if local.mod_grafana_db_create && !local.mod_grafana_db_is_serverless }

  apply_immediately                     = try(each.value.apply_immediately, local.modin_grafana_db_apply_immediately)
  auto_minor_version_upgrade            = try(each.value.auto_minor_version_upgrade, local.modin_grafana_db_auto_minor_version_upgrade)
  availability_zone                     = try(each.value.availability_zone, null)
  ca_cert_identifier                    = local.modin_grafana_db_ca_cert_identifier
  cluster_identifier                    = aws_rds_cluster.mod_grafana_db_this[0].id
  copy_tags_to_snapshot                 = try(each.value.copy_tags_to_snapshot, local.modin_grafana_db_copy_tags_to_snapshot)
  db_parameter_group_name               = local.modin_grafana_db_create_db_parameter_group ? aws_db_parameter_group.mod_grafana_db_this[0].id : try(each.value.db_parameter_group_name, local.modin_grafana_db_db_parameter_group_name)
  db_subnet_group_name                  = local.mod_grafana_db_db_subnet_group_name
  engine                                = local.modin_grafana_db_engine
  engine_version                        = local.modin_grafana_db_engine_version
  identifier                            = local.modin_grafana_db_instances_use_identifier_prefix ? null : try(each.value.identifier, "${local.modin_grafana_db_name}-${each.key}")
  identifier_prefix                     = local.modin_grafana_db_instances_use_identifier_prefix ? try(each.value.identifier_prefix, "${local.modin_grafana_db_name}-${each.key}-") : null
  instance_class                        = try(each.value.instance_class, local.modin_grafana_db_instance_class)
  monitoring_interval                   = local.modin_grafana_db_cluster_monitoring_interval > 0 ? local.modin_grafana_db_cluster_monitoring_interval : try(each.value.monitoring_interval, local.modin_grafana_db_monitoring_interval)
  monitoring_role_arn                   = local.modin_grafana_db_create_monitoring_role ? try(aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].arn, null) : local.modin_grafana_db_monitoring_role_arn
  performance_insights_enabled          = try(each.value.performance_insights_enabled, local.modin_grafana_db_performance_insights_enabled)
  performance_insights_kms_key_id       = try(each.value.performance_insights_kms_key_id, local.modin_grafana_db_performance_insights_kms_key_id)
  performance_insights_retention_period = try(each.value.performance_insights_retention_period, local.modin_grafana_db_performance_insights_retention_period)
  # preferred_backup_window - is set at the cluster level and will error if provided here
  preferred_maintenance_window = try(each.value.preferred_maintenance_window, local.modin_grafana_db_preferred_maintenance_window)
  promotion_tier               = try(each.value.promotion_tier, null)
  publicly_accessible          = try(each.value.publicly_accessible, local.modin_grafana_db_publicly_accessible)
  tags                         = merge(local.modin_grafana_db_tags, try(each.value.tags, {}))

  timeouts {
    create = try(local.modin_grafana_db_instance_timeouts.create, null)
    update = try(local.modin_grafana_db_instance_timeouts.update, null)
    delete = try(local.modin_grafana_db_instance_timeouts.delete, null)
  }

  lifecycle {
    create_before_destroy = true
  }

}

################################################################################
# Cluster Endpoint(s)
################################################################################

resource "aws_rds_cluster_endpoint" "mod_grafana_db_this" {
  for_each = { for k, v in local.modin_grafana_db_endpoints : k => v if local.mod_grafana_db_create && !local.mod_grafana_db_is_serverless }

  cluster_endpoint_identifier = each.value.identifier
  cluster_identifier          = aws_rds_cluster.mod_grafana_db_this[0].id
  custom_endpoint_type        = each.value.type
  excluded_members            = try(each.value.excluded_members, null)
  static_members              = try(each.value.static_members, null)
  tags                        = merge(local.modin_grafana_db_tags, try(each.value.tags, {}))

  depends_on = [
    aws_rds_cluster_instance.mod_grafana_db_this
  ]
}

################################################################################
# Cluster IAM Roles
################################################################################

resource "aws_rds_cluster_role_association" "mod_grafana_db_this" {
  for_each = { for k, v in local.modin_grafana_db_iam_roles : k => v if local.mod_grafana_db_create }

  db_cluster_identifier = aws_rds_cluster.mod_grafana_db_this[0].id
  feature_name          = each.value.feature_name
  role_arn              = each.value.role_arn
}

################################################################################
# Enhanced Monitoring
################################################################################

locals {
  mod_grafana_db_create_monitoring_role = local.mod_grafana_db_create && local.modin_grafana_db_create_monitoring_role && (local.modin_grafana_db_monitoring_interval > 0 || local.modin_grafana_db_cluster_monitoring_interval > 0)
}

data "aws_iam_policy_document" "mod_grafana_db_monitoring_rds_assume_role" {
  count = local.mod_grafana_db_create_monitoring_role ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "mod_grafana_db_rds_enhanced_monitoring" {
  count = local.mod_grafana_db_create_monitoring_role ? 1 : 0

  name        = local.modin_grafana_db_iam_role_use_name_prefix ? null : local.modin_grafana_db_iam_role_name
  name_prefix = local.modin_grafana_db_iam_role_use_name_prefix ? "${local.modin_grafana_db_iam_role_name}-" : null
  description = local.modin_grafana_db_iam_role_description
  path        = local.modin_grafana_db_iam_role_path

  assume_role_policy    = data.aws_iam_policy_document.mod_grafana_db_monitoring_rds_assume_role[0].json
  managed_policy_arns   = local.modin_grafana_db_iam_role_managed_policy_arns
  permissions_boundary  = local.modin_grafana_db_iam_role_permissions_boundary
  force_detach_policies = local.modin_grafana_db_iam_role_force_detach_policies
  max_session_duration  = local.modin_grafana_db_iam_role_max_session_duration

  tags = local.modin_grafana_db_tags
}

resource "aws_iam_role_policy_attachment" "mod_grafana_db_rds_enhanced_monitoring" {
  count = local.mod_grafana_db_create_monitoring_role ? 1 : 0

  role       = aws_iam_role.mod_grafana_db_rds_enhanced_monitoring[0].name
  policy_arn = "arn:${data.aws_partition.mod_grafana_db_current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

################################################################################
# Autoscaling
################################################################################

resource "aws_appautoscaling_target" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_autoscaling_enabled && !local.mod_grafana_db_is_serverless ? 1 : 0

  max_capacity       = local.modin_grafana_db_autoscaling_max_capacity
  min_capacity       = local.modin_grafana_db_autoscaling_min_capacity
  resource_id        = "cluster:${aws_rds_cluster.mod_grafana_db_this[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"

  tags = local.modin_grafana_db_tags

  lifecycle {
    ignore_changes = [
      tags_all,
    ]
  }
}

resource "aws_appautoscaling_policy" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_autoscaling_enabled && !local.mod_grafana_db_is_serverless ? 1 : 0

  name               = local.modin_grafana_db_autoscaling_policy_name
  policy_type        = "TargetTrackingScaling"
  resource_id        = "cluster:${aws_rds_cluster.mod_grafana_db_this[0].cluster_identifier}"
  scalable_dimension = "rds:cluster:ReadReplicaCount"
  service_namespace  = "rds"

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = local.modin_grafana_db_predefined_metric_type
    }

    scale_in_cooldown  = local.modin_grafana_db_autoscaling_scale_in_cooldown
    scale_out_cooldown = local.modin_grafana_db_autoscaling_scale_out_cooldown
    target_value       = local.modin_grafana_db_predefined_metric_type == "RDSReaderAverageCPUUtilization" ? local.modin_grafana_db_autoscaling_target_cpu : local.modin_grafana_db_autoscaling_target_connections
  }

  depends_on = [
    aws_appautoscaling_target.mod_grafana_db_this
  ]
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_security_group ? 1 : 0

  name        = local.modin_grafana_db_security_group_use_name_prefix ? null : local.mod_grafana_db_security_group_name
  name_prefix = local.modin_grafana_db_security_group_use_name_prefix ? "${local.mod_grafana_db_security_group_name}-" : null
  vpc_id      = local.modin_grafana_db_vpc_id
  description = coalesce(local.modin_grafana_db_security_group_description, "Control traffic to/from RDS Aurora ${local.modin_grafana_db_name}")

  tags = merge(local.modin_grafana_db_tags, local.modin_grafana_db_security_group_tags, { Name = local.mod_grafana_db_security_group_name })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "mod_grafana_db_this" {
  for_each = { for k, v in local.modin_grafana_db_security_group_rules : k => v if local.mod_grafana_db_create && local.modin_grafana_db_create_security_group }

  # required
  type              = try(each.value.type, "ingress")
  from_port         = try(each.value.from_port, local.mod_grafana_db_port)
  to_port           = try(each.value.to_port, local.mod_grafana_db_port)
  protocol          = try(each.value.protocol, "tcp")
  security_group_id = aws_security_group.mod_grafana_db_this[0].id

  # optional
  cidr_blocks              = try(each.value.cidr_blocks, null)
  description              = try(each.value.description, null)
  ipv6_cidr_blocks         = try(each.value.ipv6_cidr_blocks, null)
  prefix_list_ids          = try(each.value.prefix_list_ids, null)
  source_security_group_id = try(each.value.source_security_group_id, null)
  self                     = try(each.value.self, null)
}

################################################################################
# Cluster Parameter Group
################################################################################

resource "aws_rds_cluster_parameter_group" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_db_cluster_parameter_group ? 1 : 0

  name        = local.modin_grafana_db_db_cluster_parameter_group_use_name_prefix ? null : local.mod_grafana_db_cluster_parameter_group_name
  name_prefix = local.modin_grafana_db_db_cluster_parameter_group_use_name_prefix ? "${local.mod_grafana_db_cluster_parameter_group_name}-" : null
  description = local.modin_grafana_db_db_cluster_parameter_group_description
  family      = local.modin_grafana_db_db_cluster_parameter_group_family

  dynamic "parameter" {
    for_each = local.modin_grafana_db_db_cluster_parameter_group_parameters

    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = try(parameter.value.apply_method, "immediate")
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.modin_grafana_db_tags
}

################################################################################
# DB Parameter Group
################################################################################

resource "aws_db_parameter_group" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_db_parameter_group ? 1 : 0

  name        = local.modin_grafana_db_db_parameter_group_use_name_prefix ? null : local.mod_grafana_db_db_parameter_group_name
  name_prefix = local.modin_grafana_db_db_parameter_group_use_name_prefix ? "${local.mod_grafana_db_db_parameter_group_name}-" : null
  description = local.modin_grafana_db_db_parameter_group_description
  family      = local.modin_grafana_db_db_parameter_group_family

  dynamic "parameter" {
    for_each = local.modin_grafana_db_db_parameter_group_parameters

    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = try(parameter.value.apply_method, "immediate")
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.modin_grafana_db_tags
}

################################################################################
# CloudWatch Log Group
################################################################################

# Log groups will not be created if using a cluster identifier prefix
resource "aws_cloudwatch_log_group" "mod_grafana_db_this" {
  for_each = toset([for log in local.modin_grafana_db_enabled_cloudwatch_logs_exports : log if local.mod_grafana_db_create && local.modin_grafana_db_create_cloudwatch_log_group && !local.modin_grafana_db_cluster_use_name_prefix])

  name              = "/aws/rds/cluster/${local.modin_grafana_db_name}/${each.value}"
  retention_in_days = local.modin_grafana_db_cloudwatch_log_group_retention_in_days
  kms_key_id        = local.modin_grafana_db_cloudwatch_log_group_kms_key_id
  skip_destroy      = local.modin_grafana_db_cloudwatch_log_group_skip_destroy
  log_group_class   = local.modin_grafana_db_cloudwatch_log_group_class

  tags = merge(local.modin_grafana_db_tags, local.modin_grafana_db_cloudwatch_log_group_tags)
}

################################################################################
# Cluster Activity Stream
################################################################################

resource "aws_rds_cluster_activity_stream" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_db_cluster_activity_stream ? 1 : 0

  resource_arn                        = aws_rds_cluster.mod_grafana_db_this[0].arn
  mode                                = local.modin_grafana_db_db_cluster_activity_stream_mode
  kms_key_id                          = local.modin_grafana_db_db_cluster_activity_stream_kms_key_id
  engine_native_audit_fields_included = local.modin_grafana_db_engine_native_audit_fields_included

  depends_on = [aws_rds_cluster_instance.mod_grafana_db_this]
}

################################################################################
# Managed Secret Rotation
################################################################################

# There is not currently a way to disable secret rotation on an initial apply.
# In order to use master password secrets management without a rotation, the following workaround can be used:
# `manage_master_user_password_rotation` must be set to true first and applied followed by setting it to false and another apply.
# Note: when setting `manage_master_user_password_rotation` to true, a schedule must also be set using `master_user_password_rotation_schedule_expression` or `master_user_password_rotation_automatically_after_days`.
# To prevent password from being immediately rotated when implementing this workaround, set `master_user_password_rotate_immediately` to false.
# See: https://github.com/hashicorp/terraform-provider-aws/issues/37779
resource "aws_secretsmanager_secret_rotation" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_manage_master_user_password && local.modin_grafana_db_manage_master_user_password_rotation ? 1 : 0

  secret_id          = aws_rds_cluster.mod_grafana_db_this[0].master_user_secret[0].secret_arn
  rotate_immediately = local.modin_grafana_db_master_user_password_rotate_immediately

  rotation_rules {
    automatically_after_days = local.modin_grafana_db_master_user_password_rotation_automatically_after_days
    duration                 = local.modin_grafana_db_master_user_password_rotation_duration
    schedule_expression      = local.modin_grafana_db_master_user_password_rotation_schedule_expression
  }
}

################################################################################
# RDS Shard Group
################################################################################

resource "aws_rds_shard_group" "mod_grafana_db_this" {
  count = local.mod_grafana_db_create && local.modin_grafana_db_create_shard_group ? 1 : 0

  compute_redundancy        = local.modin_grafana_db_compute_redundancy
  db_cluster_identifier     = aws_rds_cluster.mod_grafana_db_this[0].id
  db_shard_group_identifier = local.modin_grafana_db_db_shard_group_identifier
  max_acu                   = local.modin_grafana_db_max_acu
  min_acu                   = local.modin_grafana_db_min_acu
  publicly_accessible       = local.modin_grafana_db_publicly_accessible
  tags                      = merge(local.modin_grafana_db_tags, local.modin_grafana_db_shard_group_tags)

  timeouts {
    create = try(local.modin_grafana_db_shard_group_timeouts.create, null)
    update = try(local.modin_grafana_db_shard_group_timeouts.update, null)
    delete = try(local.modin_grafana_db_shard_group_timeouts.delete, null)
  }
}

## END INLINE module grafana_db

resource "aws_route53_record" "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  zone_id = var.tfe_outputs_root_dns_nonsensitive_values.internal_root_zone_id
  name    = "${local.grafana_db_name}-db.eks"
  type    = "CNAME"
  ttl     = 300
  records = [local.modout_grafana_db_cluster_endpoint]
}

resource "aws_secretsmanager_secret" "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  name                    = "${module.eks.cluster_name}/grafana/database"
  recovery_window_in_days = var.secrets_recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  secret_id = aws_secretsmanager_secret.grafana_db[count.index].id
  secret_string = jsonencode({
    "engine"   = "aurora"
    "host"     = aws_route53_record.grafana_db[count.index].fqdn
    "username" = local.modout_grafana_db_cluster_master_username
    "password" = local.modout_grafana_db_cluster_master_password
    "dbname"   = local.grafana_db_name
    "port"     = local.modout_grafana_db_cluster_port
  })
}
