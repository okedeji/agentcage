// dir_fuzz — ffuf directory/file fuzzing under a base path. Brute-
// forces common file/directory names from an embedded wordlist and
// returns paths that responded with non-404 status. Use when crawling
// found nothing or to discover hidden admin/config endpoints.

import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { runCmd } from '../../lib/cmd';
import { auth } from '../../lib/auth';
import { env } from '../../lib/env';
import { DiscoveryTool } from './types';

interface Args {
  base_path: string;
  wordlist_size?: number;
}

// Curated common path/file names ordered by likelihood. Capped at 200
// per invocation to keep cage time bounded; the agent can call again
// against a different base_path.
const COMMON_PATHS = [
  'admin', 'api', 'login', 'logout', 'register', 'signup', 'signin',
  'dashboard', 'account', 'profile', 'settings', 'config', 'configuration',
  'users', 'user', 'auth', 'oauth', 'token', 'tokens', 'session',
  'docs', 'doc', 'documentation', 'swagger', 'openapi', 'graphql',
  'health', 'healthz', 'status', 'ping', 'version', 'metrics', 'debug',
  'test', 'tests', 'staging', 'dev', 'sandbox', 'demo',
  'v1', 'v2', 'v3', 'api/v1', 'api/v2',
  'static', 'assets', 'public', 'uploads', 'files', 'media', 'images',
  '.env', '.git', '.git/config', '.git/HEAD', '.gitignore', '.dockerignore',
  '.htaccess', '.htpasswd', '.well-known',
  'robots.txt', 'sitemap.xml', 'humans.txt', 'security.txt',
  'backup', 'backups', 'old', 'tmp', 'temp', 'archive',
  'database.sql', 'dump.sql', 'backup.zip',
  'phpinfo.php', 'info.php', 'server-status', 'server-info',
  'wp-admin', 'wp-login.php', 'wp-config.php',
  'console', 'shell', 'webshell', 'manager', 'cmd',
  'admin/login', 'admin/index', 'admin.php', 'admin.html',
  'install', 'setup', 'wizard',
  'redis', 'mongo', 'mysql', 'postgres', 'elastic',
  'kibana', 'grafana', 'prometheus', 'jenkins', 'gitlab',
  'jolokia', 'actuator', 'actuator/env', 'actuator/health',
  'cgi-bin', 'cgi-bin/test', 'php-cgi',
  'invoke', 'rpc', 'rpc/list',
  'callback', 'webhook', 'webhooks',
];

async function run(rawArgs: Record<string, unknown>): Promise<string> {
  const args = rawArgs as unknown as Args;
  if (typeof args.base_path !== 'string') {
    return 'ERROR: dir_fuzz requires a string `base_path` argument';
  }
  const size = Math.max(20, Math.min(args.wordlist_size ?? 100, 200));
  const wordlist = COMMON_PATHS.slice(0, size).join('\n');

  const tmp = mkdtempSync(join(tmpdir(), 'ffuf-disc-'));
  const wordlistPath = join(tmp, 'wordlist.txt');
  const outputPath = join(tmp, 'output.json');
  writeFileSync(wordlistPath, wordlist);

  const base = args.base_path.replace(/\/$/, '');
  const url = `https://${env.target}${base}/FUZZ`;
  const ffufArgs = ['-u', url, '-w', wordlistPath, '-mc', '200,301,302,401,403', '-t', '10', '-o', outputPath, '-of', 'json', '-s'];
  if (auth?.type === 'header') ffufArgs.push('-H', `${auth.name}: ${auth.value}`);
  if (auth?.type === 'cookie') ffufArgs.push('-b', `${auth.name}=${auth.value}`);

  const { stderr } = await runCmd('ffuf', ffufArgs, 90_000);

  let results: Array<{ input: { FUZZ?: string }; status: number; length: number }> = [];
  if (existsSync(outputPath)) {
    try {
      const parsed = JSON.parse(readFileSync(outputPath, 'utf8'));
      results = parsed.results ?? [];
    } catch {
      // ffuf output unreadable
    }
  }

  if (results.length === 0) {
    return `ffuf found no responsive paths under ${base} (tried ${size} candidates; stderr: ${stderr.slice(0, 200)})`;
  }
  const lines = results
    .slice(0, 50)
    .map((r) => `  ${base}/${r.input.FUZZ ?? '?'} → ${r.status} (${r.length}B)`)
    .join('\n');
  return `Found ${results.length} responsive paths under ${base}:\n${lines}`;
}

export const dirFuzz: DiscoveryTool = {
  name: 'dir_fuzz',
  description: 'Directory/file fuzz under a base path using ffuf with a curated wordlist of common admin/api/config endpoints. Use when crawling did not find enough surface or you suspect hidden endpoints.',
  parameters: {
    type: 'object',
    properties: {
      base_path: { type: 'string', description: 'Base path to fuzz under (e.g. / or /api). FUZZ tokens are appended.' },
      wordlist_size: { type: 'integer', description: 'How many candidates to try, 20-200 (default 100). Higher = more thorough but slower.' },
    },
    required: ['base_path'],
  },
  run,
};
