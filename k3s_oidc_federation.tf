# The k3s cluster as an OIDC identity provider for the External Secrets Operator: see README, "k3s OIDC federation" (ADR 0032).

locals {
  k3s_oidc_issuer_host = aws_cloudfront_distribution.k3s_oidc.domain_name
  k3s_oidc_issuer      = "https://${local.k3s_oidc_issuer_host}"

  # Per namespace, the Secrets Manager groups its Pods hold as Kubernetes Secrets today.
  k3s_eso_secret_groups = {
    apps = [
      "home-infra/blocky",
      "home-infra/ingress",
      "home-infra/monitoring",
      # Nextcloud's OIDC client secret, shared with AIO until the ADR 0033 cutover.
      "home-infra/nextcloud",
      "k3s-apps/bulwark",
      "k3s-apps/ghcr-pull-token",
      "k3s-apps/nextcloud",
      "k3s-apps/paperless",
      "k3s-apps/sankey-export",
      "k3s-apps/vaultwarden",
    ]
    auth = [
      "home-infra/authelia",
      "home-infra/monitoring",
    ]
    monitoring = [
      "home-infra/blocky",
      "home-infra/grafana",
      "home-infra/monitoring",
    ]
  }
}

#trivy:ignore:AVD-AWS-0089
#trivy:ignore:AVD-AWS-0090
resource "aws_s3_bucket" "k3s_oidc" {
  # Holds two public documents, rebuilt by every apply: no access logs or versions needed.
  bucket = "jkandler-k3s-oidc"
}

resource "aws_s3_bucket_public_access_block" "k3s_oidc" {
  bucket = aws_s3_bucket.k3s_oidc.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "k3s_oidc" {
  bucket = aws_s3_bucket.k3s_oidc.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# The shared key's policy already lets CloudFront decrypt for OAC origins (README, "Shared KMS key").
resource "aws_s3_bucket_server_side_encryption_configuration" "k3s_oidc" {
  bucket = aws_s3_bucket.k3s_oidc.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.shared.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "k3s_oidc" {
  bucket = aws_s3_bucket.k3s_oidc.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudFrontReadOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.k3s_oidc.arn}/*"
        Condition = {
          StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.k3s_oidc.arn }
        }
      },
    ]
  })
}

resource "aws_cloudfront_origin_access_control" "k3s_oidc" {
  name                              = "k3s-oidc"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

#trivy:ignore:AVD-AWS-0011
resource "aws_cloudfront_distribution" "k3s_oidc" {
  # Serves two small public documents to AWS STS: a WAF would cost more than anything it protects.
  comment         = "k3s OIDC issuer (ADR 0032)"
  enabled         = true
  is_ipv6_enabled = true
  price_class     = "PriceClass_100"

  origin {
    origin_id                = "k3s-oidc"
    domain_name              = aws_s3_bucket.k3s_oidc.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.k3s_oidc.id
  }

  default_cache_behavior {
    target_origin_id       = "k3s-oidc"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    # Managed policy "CachingOptimized".
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # Its domain name is the issuer in every ServiceAccount token and in the OIDC provider.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_object" "k3s_oidc_discovery" {
  bucket       = aws_s3_bucket.k3s_oidc.id
  key          = ".well-known/openid-configuration"
  content_type = "application/json"
  content = jsonencode({
    issuer                                = local.k3s_oidc_issuer
    jwks_uri                              = "${local.k3s_oidc_issuer}/openid/v1/jwks"
    response_types_supported              = ["id_token"]
    subject_types_supported               = ["public"]
    id_token_signing_alg_values_supported = ["RS256"]
  })
}

resource "aws_s3_object" "k3s_oidc_jwks" {
  bucket       = aws_s3_bucket.k3s_oidc.id
  key          = "openid/v1/jwks"
  content_type = "application/json"
  source       = "${path.module}/k3s-oidc/jwks.json"
  etag         = filemd5("${path.module}/k3s-oidc/jwks.json")
}

resource "aws_iam_openid_connect_provider" "k3s" {
  url            = local.k3s_oidc_issuer
  client_id_list = ["sts.amazonaws.com"]

  # AWS reads the issuer when it creates the provider, so the documents must be served first.
  depends_on = [aws_s3_object.k3s_oidc_discovery, aws_s3_object.k3s_oidc_jwks, aws_s3_bucket_policy.k3s_oidc]

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "k3s_eso" {
  for_each = local.k3s_eso_secret_groups

  name = "k3s-eso-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Federated = aws_iam_openid_connect_provider.k3s.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.k3s_oidc_issuer_host}:sub" = "system:serviceaccount:${each.key}:external-secrets"
            "${local.k3s_oidc_issuer_host}:aud" = "sts.amazonaws.com"
          }
        }
      },
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy" "k3s_eso" {
  for_each = local.k3s_eso_secret_groups

  name = "read-secrets"
  role = aws_iam_role.k3s_eso[each.key].id

  # "-??????" is Secrets Manager's ARN suffix, so "home-infra/authelia" never matches "home-infra/authelia-oidc".
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadNamespaceSecrets"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = [
          for group in each.value :
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${group}-??????"
        ]
      },
    ]
  })
}
