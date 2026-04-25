import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as zlib from 'zlib';

const SUPPORTED_RUNTIMES = new Set(['python3', 'node', 'go', 'static']);

export interface CagefileManifest {
  runtime: string;
  entrypoint: string;
  systemDeps?: string[];
  packages?: string[];
  pipDeps?: string[];
  npmDeps?: string[];
  goDeps?: string[];
}

export interface BundleManifest {
  name: string;
  version: string;
  runtime: string;
  entrypoint: string;
  system_deps?: string[];
  packages?: string[];
  pip_deps?: string[];
  npm_deps?: string[];
  go_deps?: string[];
  files_hash: string;
}

export interface PackResult {
  outputPath: string;
  manifest: BundleManifest;
  bundleRef: string;
}

export interface PackOptions {
  output?: string;
  version?: string;
}

export async function pack(dir: string, options: PackOptions = {}): Promise<PackResult> {
  const absDir = path.resolve(dir);
  if (!fs.statSync(absDir).isDirectory()) {
    throw new Error(`${dir} is not a directory`);
  }

  const cagefilePath = path.join(absDir, 'Cagefile');
  if (!fs.existsSync(cagefilePath)) {
    throw new Error(`no Cagefile found in ${dir}`);
  }

  const manifest = parseCagefile(fs.readFileSync(cagefilePath, 'utf-8'));
  const filesHash = hashDirectory(absDir);

  const bundleManifest: BundleManifest = {
    name: path.basename(absDir),
    version: options.version ?? '0.1.0',
    runtime: manifest.runtime,
    entrypoint: manifest.entrypoint,
    system_deps: manifest.systemDeps,
    packages: manifest.packages,
    pip_deps: manifest.pipDeps,
    npm_deps: manifest.npmDeps,
    go_deps: manifest.goDeps,
    files_hash: 'sha256:' + filesHash,
  };

  const manifestBytes = Buffer.from(JSON.stringify(bundleManifest, null, 2));
  const manifestHash = sha256Hex(manifestBytes);

  const signature = {
    manifest_hash: 'sha256:' + manifestHash,
  };
  const sigBytes = Buffer.from(JSON.stringify(signature, null, 2));

  // Build tar archive: manifest.json + signature.json + files/*
  const tarChunks: Buffer[] = [];
  appendToTar(tarChunks, 'manifest.json', manifestBytes);
  appendToTar(tarChunks, 'signature.json', sigBytes);
  appendDirToTar(tarChunks, absDir, 'files');
  // Tar end-of-archive marker: two 512-byte zero blocks.
  tarChunks.push(Buffer.alloc(1024));

  const tarBuffer = Buffer.concat(tarChunks);
  const gzipped = zlib.gzipSync(tarBuffer);

  const outputPath = options.output ?? path.basename(absDir) + '.cage';
  fs.writeFileSync(outputPath, gzipped);

  const bundleRef = sha256Hex(gzipped);

  return { outputPath, manifest: bundleManifest, bundleRef };
}

function parseCagefile(content: string): CagefileManifest {
  const m: CagefileManifest = { runtime: '', entrypoint: '' };

  for (const [i, raw] of content.split('\n').entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const spaceIdx = line.indexOf(' ');
    if (spaceIdx < 0) throw new Error(`Cagefile line ${i + 1}: directive "${line}" requires a value`);

    const directive = line.slice(0, spaceIdx).toLowerCase();
    const value = line.slice(spaceIdx + 1).trim();

    switch (directive) {
      case 'runtime':
        if (!SUPPORTED_RUNTIMES.has(value)) {
          throw new Error(`Cagefile line ${i + 1}: unsupported runtime "${value}"`);
        }
        m.runtime = value;
        break;
      case 'entrypoint':
        m.entrypoint = value;
        break;
      case 'deps':
        m.systemDeps = [...(m.systemDeps ?? []), ...value.split(/\s+/)];
        break;
      case 'packages':
        m.packages = [...(m.packages ?? []), ...value.split(/\s+/)];
        break;
      case 'pip':
        m.pipDeps = [...(m.pipDeps ?? []), ...value.split(/\s+/)];
        break;
      case 'npm':
        m.npmDeps = [...(m.npmDeps ?? []), ...value.split(/\s+/)];
        break;
      case 'go-deps':
        m.goDeps = [...(m.goDeps ?? []), ...value.split(/\s+/)];
        break;
      default:
        throw new Error(`Cagefile line ${i + 1}: unknown directive "${directive}"`);
    }
  }

  if (!m.runtime) throw new Error('Cagefile: runtime is required');
  if (!m.entrypoint) throw new Error('Cagefile: entrypoint is required');
  return m;
}

function hashDirectory(dir: string): string {
  const files: string[] = [];
  collectFiles(dir, '', files);
  files.sort();

  const hash = crypto.createHash('sha256');
  for (const rel of files) {
    // Normalize path separators for cross-platform determinism.
    hash.update(rel.replace(/\\/g, '/'));
    hash.update(fs.readFileSync(path.join(dir, rel)));
  }
  return hash.digest('hex');
}

function collectFiles(base: string, rel: string, out: string[]): void {
  const absPath = rel ? path.join(base, rel) : base;
  for (const entry of fs.readdirSync(absPath, { withFileTypes: true })) {
    if (entry.name === 'Cagefile' && !rel) continue;
    const childRel = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      collectFiles(base, childRel, out);
    } else if (entry.isFile()) {
      out.push(childRel);
    }
  }
}

function sha256Hex(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Minimal tar implementation (POSIX ustar, enough for agentcage bundles).
function appendToTar(chunks: Buffer[], name: string, data: Buffer): void {
  const header = createTarHeader(name, data.length, 0o644);
  chunks.push(header);
  chunks.push(data);
  // Pad to 512-byte boundary.
  const remainder = data.length % 512;
  if (remainder > 0) chunks.push(Buffer.alloc(512 - remainder));
}

function appendDirToTar(chunks: Buffer[], srcDir: string, prefix: string): void {
  const files: string[] = [];
  collectFiles(srcDir, '', files);
  files.sort();

  for (const rel of files) {
    const tarPath = `${prefix}/${rel}`;
    const absPath = path.join(srcDir, rel);
    const data = fs.readFileSync(absPath);
    const stat = fs.statSync(absPath);
    const mode = stat.mode & 0o111 ? 0o755 : 0o644;
    const header = createTarHeader(tarPath, data.length, mode);
    chunks.push(header);
    chunks.push(data);
    const remainder = data.length % 512;
    if (remainder > 0) chunks.push(Buffer.alloc(512 - remainder));
  }
}

function createTarHeader(name: string, size: number, mode: number): Buffer {
  const header = Buffer.alloc(512);

  // name (100 bytes)
  header.write(name.slice(0, 100), 0, 100, 'utf-8');
  // mode (8 bytes, octal)
  header.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'utf-8');
  // uid (8 bytes)
  header.write('0000000\0', 108, 8, 'utf-8');
  // gid (8 bytes)
  header.write('0000000\0', 116, 8, 'utf-8');
  // size (12 bytes, octal)
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf-8');
  // mtime (12 bytes, octal)
  const mtime = Math.floor(Date.now() / 1000);
  header.write(mtime.toString(8).padStart(11, '0') + '\0', 136, 12, 'utf-8');
  // typeflag: regular file
  header.write('0', 156, 1, 'utf-8');
  // magic
  header.write('ustar\0', 257, 6, 'utf-8');
  // version
  header.write('00', 263, 2, 'utf-8');

  // Compute checksum: sum of all unsigned bytes with checksum field as spaces.
  header.write('        ', 148, 8, 'utf-8');
  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf-8');

  return header;
}
