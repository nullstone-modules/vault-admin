variable "name" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "vault_addr" {
  type = string
}

variable "vault_port" {
  type = number
}

variable "token_secret_arn" {
  type = string
}

variable "network" {
  type = object({
    vpc_id                  = string
    vault_security_group_id = string
    subnet_ids              = list(string)
  })
}
