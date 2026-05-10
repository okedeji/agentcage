# Known issues

## Secrets in Terraform user data

**Status:** open
**Severity:** low (dev), high (prod)
**Affects:** `infra/terraform/modules/aws/agentcage/`

The Terraform module passes secrets to the instance via EC2 user data. This has two security gaps:

1. **User data is readable via the AWS API.** Any IAM principal with `ec2:DescribeInstanceAttribute` can retrieve the user data, which contains the plaintext secrets.
2. **Terraform state contains secrets in plaintext.** Even with `sensitive = true`, the values are stored in `terraform.tfstate`. Local state files or unencrypted S3 backends expose them.

**Acceptable for:** dev and test environments where the instance is short-lived and the AWS account is single-user.

**Not acceptable for:** production, shared accounts, or long-lived instances.

**Fix:** Use AWS Secrets Manager or SSM Parameter Store. The instance IAM role fetches secrets at boot instead of receiving them through user data. This removes secrets from both the Terraform state and the instance metadata.

## macOS not supported

**Status:** resolved (removed)
**Details:** see [docs/macos-removal.md](macos-removal.md)

agentcage requires Linux with `/dev/kvm`. The macOS support layer (Apple Virtualization.framework with nested KVM) was removed because Apple VZ does not expose VHE to the guest CPU, preventing Firecracker guests from booting. CLI commands (`run`, `logs`, `findings`) work from macOS against a remote Linux orchestrator.
