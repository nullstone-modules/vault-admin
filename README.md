# vault-admin

Shared Go admin for Vault, with an AWS module and a GCP module.

Both entrypoints call the same writer. The writer creates one Vault AWS auth role bound to one IAM principal. It rejects platform policies (`operator`, `admin`, `aws-auth`, `provisioning`, `root`, `default`) and any `tenant-*` policy. It also rejects a role name already bound to another principal, and a principal already bound to another role.

`make package` builds the zip each module publishes. The Vault cluster references `api.nullstone.io/nullstone/aws-vault-admin/aws`.

The AWS function reads the Vault token from Secrets Manager at invoke time. The GCP function receives it as `VAULT_TOKEN`. The token is not returned to the app.
