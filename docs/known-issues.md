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

## SDK distributed via GitHub release tarball, not npm

**Status:** open (workaround in place)
**Severity:** low
**Affects:** `sdk/typescript/`, `internal/cagefile/install.go`, `cmd/agentcage/cmd_sdk.go`

The `@agentcage/sdk` TypeScript package is not published to the npm registry. npm publish requires an OTP (one-time password) that could not be configured during initial development.

**Workaround:** The SDK is distributed as an npm-compatible tarball (`agentcage-sdk-X.Y.Z.tgz`) attached to each GitHub release. The orchestrator downloads it during `agentcage init` to `~/.agentcage/bin/agentcage-sdk.tgz`. During `agentcage pack`, the dependency resolver rewrites `@agentcage/sdk` in the agent's `package.json` to a `file://` path pointing at the cached tarball. This makes `npm install` resolve the SDK offline without a registry.

**User-facing behavior:**
- `agentcage sdk install` installs the SDK into the current project from the local cache.
- Agents declare `@agentcage/sdk` as a normal dependency. It resolves at pack time, not install time.
- No npm authentication or registry access is needed.

**Fix:** Publish `@agentcage/sdk` to npm (or a private registry) and remove the `file://` rewriting in `cagefile/install.go`. This would let agents install the SDK via standard `npm install` without the orchestrator.

## macOS not supported

**Status:** resolved (removed)
**Details:** see [docs/macos-removal.md](macos-removal.md)

agentcage requires Linux with `/dev/kvm`. The macOS support layer (Apple Virtualization.framework with nested KVM) was removed because Apple VZ does not expose VHE to the guest CPU, preventing Firecracker guests from booting. CLI commands (`run`, `logs`, `findings`) work from macOS against a remote Linux orchestrator.
