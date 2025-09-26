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

module "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 9.0"

  name              = local.grafana_db_name
  database_name     = "grafana"
  engine            = "aurora-postgresql"
  engine_mode       = "provisioned"
  engine_version    = data.aws_rds_engine_version.postgresql[count.index].version
  storage_encrypted = true

  allow_major_version_upgrade = true

  vpc_id                 = var.tfe_outputs_vpc_nonsensitive_values.id
  subnets                = local.grafana_subnet_ids
  create_db_subnet_group = true
  create_security_group  = true
  security_group_rules = {
    from_cluster = { source_security_group_id = module.eks.cluster_primary_security_group_id }
  }
  manage_master_user_password = false
  master_username             = "root"
  master_password             = random_password.grafana_db[count.index].result

  serverlessv2_scaling_configuration = {
    max_capacity             = 256
    min_capacity             = 0
    seconds_until_auto_pause = 300
  }

  instance_class = "db.serverless"
  instances = {
    one = {
      identifier = "${local.grafana_db_name}-instance-1"
    }
  }

  apply_immediately            = var.rds_apply_immediately
  backup_retention_period      = var.rds_backup_retention_period
  skip_final_snapshot          = var.rds_skip_final_snapshot
  final_snapshot_identifier    = "${local.grafana_db_name}-final"
  preferred_backup_window      = "02:00-03:00"
  preferred_maintenance_window = "sun:04:00-sun:05:00"
}

resource "aws_route53_record" "grafana_db" {
  count = startswith(var.govuk_environment, "eph-") ? 0 : 1

  zone_id = var.tfe_outputs_root_dns_nonsensitive_values.internal_root_zone_id
  name    = "${local.grafana_db_name}-db.eks"
  type    = "CNAME"
  ttl     = 300
  records = [module.grafana_db[count.index].cluster_endpoint]
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
    "username" = module.grafana_db[count.index].cluster_master_username
    "password" = module.grafana_db[count.index].cluster_master_password
    "dbname"   = local.grafana_db_name
    "port"     = module.grafana_db[count.index].cluster_port
  })
}
