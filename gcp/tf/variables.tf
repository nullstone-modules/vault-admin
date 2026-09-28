variable "name" {
  type = string

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,52}[a-z0-9])?$", var.name))
    error_message = "name must be a lowercase DNS label of at most 54 characters."
  }
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "vault_addr" {
  type = string
}

variable "token_secret_id" {
  type = string
}

variable "vpc_access_connector_name" {
  type = string
}

variable "invoker_impersonators" {
  type    = list(string)
  default = []
}
