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

The writer binds exactly one principal per role. It grants only the cluster's tenant broker policies, `apps-reader` or `apps-writer`; platform, tenant, and custom policies are rejected. It also rejects a role name already bound to another principal, and a principal already bound to another role. The cluster owns the mounts: a missing one fails with `auth/<mount> not enabled: run bootstrap on the cluster`.

`env` is optional. On a shared cluster (`aws-ec2-vault-cluster` output `shared = true`) the capability sends the app's Nullstone env name. The writer then gives the role an identity entity named `<method>/<name>` with metadata `env`, aliased by the role's `role_id`, so every login through that role lands on it and the cluster's broker policies confine the app to `env`. Delete removes the entity, then the role. Without `env`, identity is never touched, which an unshared cluster's `apps-auth` policy also forbids. The entity never carries policies.

`make package` builds the zip each module publishes. The Vault cluster references `api.nullstone.io/nullstone/aws-vault-admin/aws`.

The AWS function holds no token. Per invoke it logs in on `auth/aws/login` as role `apps-auth` with a signed `sts:GetCallerIdentity` from its execution role (output `role_arn`), signed for `AWS_REGION`; the cluster binds that role at bootstrap. The token carries the `apps-auth` policy, lasts 5 minutes, and is revoked when the invoke ends. A 403 on login means the function role is not bound on `auth/aws/role/apps-auth`: run bootstrap or `vault-utils configure` on the cluster. The GCP function still receives a token as `VAULT_TOKEN`. No token is returned to the app.

Set `tls_server_name` (`VAULT_TLS_SERVER_NAME`) when the Vault certificate names a host other than `vault_addr`.
