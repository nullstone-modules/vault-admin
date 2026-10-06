resource "aws_security_group" "this" {
  name   = var.name
  vpc_id = var.network.vpc_id
  tags   = merge(var.tags, { Name = var.name })
}

resource "aws_security_group_rule" "to_vault" {
  security_group_id        = aws_security_group.this.id
  type                     = "egress"
  protocol                 = "tcp"
  from_port                = var.vault_port
  to_port                  = var.vault_port
  source_security_group_id = var.network.vault_security_group_id
}

# Secrets Manager has no managed prefix list; the function reaches it over NAT or a VPC endpoint.
resource "aws_security_group_rule" "to_secrets" {
  security_group_id = aws_security_group.this.id
  type              = "egress"
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "vault_from_this" {
  security_group_id        = var.network.vault_security_group_id
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = var.vault_port
  to_port                  = var.vault_port
  source_security_group_id = aws_security_group.this.id
}

resource "aws_iam_role" "this" {
  name = var.name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "basic" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "vpc" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "this" {
  role = aws_iam_role.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = var.token_secret_arn
    }]
  })
}

resource "aws_lambda_function" "this" {
  function_name    = var.name
  role             = aws_iam_role.this.arn
  runtime          = "provided.al2023"
  handler          = "bootstrap"
  filename         = "${path.module}/files/vault-admin.zip"
  source_code_hash = filebase64sha256("${path.module}/files/vault-admin.zip")
  timeout          = 15
  tags             = var.tags

  environment {
    variables = {
      VAULT_ADDR            = var.vault_addr
      VAULT_TOKEN_SECRET_ID = var.token_secret_arn
      VAULT_TLS_SERVER_NAME = var.tls_server_name
    }
  }

  vpc_config {
    subnet_ids         = var.network.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }
}
