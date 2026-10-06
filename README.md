# vault-admin

Shared Go admin for Vault, with an AWS module and a GCP module.

Both entrypoints call the same writer. An event names one app principal and the auth method it logs in with:

```json
{"data": {"name": "billing", "method": "aws", "principal": "arn:aws:iam::123456789012:role/billing", "policies": ["billing"]}, "tf": {"action": "create"}}
```

| `method` | Vault mount | `principal` | Role written |
|---|---|---|---|
| `aws` | `auth/aws` | IAM role or user ARN | `auth_type=iam`, `bound_iam_principal_arn` |
| `gcp` | `auth/gcp` | Service account email | `type=iam`, `bound_service_accounts` |

The writer enables the mount if needed and binds exactly one principal per role. It grants only the cluster's tenant broker policies, `apps-reader` or `apps-writer`; platform, tenant, and custom policies are rejected. It also rejects a role name already bound to another principal, and a principal already bound to another role. The function holds the cluster's `apps-auth` token, which can write roles on these mounts and nothing else.

`make package` builds the zip each module publishes. The Vault cluster references `api.nullstone.io/nullstone/aws-vault-admin/aws`.

The AWS function reads the Vault token from Secrets Manager at invoke time. The GCP function receives it as `VAULT_TOKEN`. The token is not returned to the app.

Set `tls_server_name` (`VAULT_TLS_SERVER_NAME`) when the Vault certificate names a host other than `vault_addr`.
