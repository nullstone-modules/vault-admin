output "function_name" {
  value = aws_lambda_function.this.function_name
}

output "role_arn" {
  value       = aws_iam_role.this.arn
  description = "Execution role of the function. The cluster binds it on auth/aws/role/apps-auth."
}
