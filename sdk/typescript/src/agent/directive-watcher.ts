import * as fs from 'fs';
import type { Directive, DirectiveInstruction } from '../types/agent';

const DEFAULT_PATH = '/var/run/agentcage/directives.json';

export type DirectiveCallback = (directive: DirectiveInstruction) => void;

export class DirectiveWatcher {
  private path: string;
  private lastSequence = -1;
  private watcher: fs.FSWatcher | null = null;
  private pollTimer: NodeJS.Timeout | null = null;

  constructor(path: string = DEFAULT_PATH) {
    this.path = path;
  }

  watch(callback: DirectiveCallback, pollIntervalMs = 1000): void {
    const check = () => {
      try {
        const raw = fs.readFileSync(this.path, 'utf-8');
        const directive: Directive = JSON.parse(raw);
        if (directive.sequence <= this.lastSequence) return;
        this.lastSequence = directive.sequence;
        for (const instruction of directive.instructions) {
          callback(instruction);
        }
      } catch {
        // File doesn't exist yet or invalid JSON. Normal during cage startup.
      }
    };

    // Try fs.watch first, fall back to polling.
    try {
      this.watcher = fs.watch(this.path, () => check());
    } catch {
      // File doesn't exist yet; use polling.
    }

    this.pollTimer = setInterval(check, pollIntervalMs);
    check();
  }

  close(): void {
    this.watcher?.close();
    this.watcher = null;
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
