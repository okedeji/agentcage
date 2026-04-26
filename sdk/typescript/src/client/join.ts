export interface JoinOptions {
  /** Orchestrator address (host:port). */
  orchestratorAddress: string;
  /** API key for authenticating with the orchestrator. */
  apiKey: string;
  /** Skip TLS for dev/localhost. */
  insecure?: boolean;
  /** URL to download cage rootfs. */
  rootfsUrl?: string;
  /** URL to download the agentcage binary. Defaults to GitHub releases. */
  agentcageBinaryUrl?: string;
  /** agentcage version to download. Defaults to 0.1.0. */
  version?: string;
}

/**
 * Generates a bash script that sets up a bare-metal cage host.
 *
 * The script downloads the agentcage binary and runs `agentcage join`
 * which handles everything else: downloading Firecracker, Falco, SPIRE agent,
 * Nomad client, configuring them to point at the orchestrator, and starting
 * them via systemd.
 *
 * Use as user_data when provisioning a new instance:
 *
 * ```typescript
 * const setup = generateJoinScript({
 *   orchestratorAddress: 'orchestrator.internal:9090',
 *   apiKey: 'ak-xxx',
 * });
 * await ec2.runInstances({ UserData: Buffer.from(setup).toString('base64'), ... });
 * ```
 */
export function generateJoinScript(options: JoinOptions): string {
  const version = options.version ?? '0.1.0';
  const binaryUrl = options.agentcageBinaryUrl ??
    `https://github.com/okedeji/agentcage/releases/download/v${version}/agentcage-linux-\${ARCH}`;

  const flags = [
    `--orchestrator ${options.orchestratorAddress}`,
    `--api-key ${options.apiKey}`,
  ];
  if (options.insecure) {
    flags.push('--insecure');
  }
  if (options.rootfsUrl) {
    flags.push(`--rootfs-url ${options.rootfsUrl}`);
  }

  return `#!/bin/bash
set -euo pipefail

# Detect architecture.
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

echo "Setting up agentcage cage host..."

# Download agentcage binary if not present.
if ! command -v agentcage &>/dev/null; then
  echo "Downloading agentcage binary..."
  curl -fsSL "${binaryUrl}" -o /usr/local/bin/agentcage
  chmod +x /usr/local/bin/agentcage
fi

# Run join — downloads all dependencies, configures services, starts systemd units.
agentcage join ${flags.join(' ')}

echo "Cage host setup complete."
`;
}
