import * as net from 'net';
import type { HoldRequest, HoldResponse } from '../types/agent';

const DEFAULT_SOCKET = '/var/run/agentcage/hold.sock';

export async function requestHold(
  req: HoldRequest,
  socketPath: string = DEFAULT_SOCKET,
): Promise<HoldResponse> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(socketPath, () => {
      const payload = JSON.stringify(req) + '\n';
      sock.write(payload);
    });

    let data = '';
    sock.on('data', (chunk) => {
      data += chunk.toString();
    });

    sock.on('end', () => {
      try {
        const resp: HoldResponse = JSON.parse(data.trim());
        resolve(resp);
      } catch (err) {
        reject(new Error(`invalid hold response: ${data}`));
      }
    });

    sock.on('error', (err) => {
      reject(new Error(`hold socket error: ${err.message}`));
    });

    sock.setTimeout(30 * 60 * 1000, () => {
      sock.destroy();
      reject(new Error('hold request timed out (30 minutes)'));
    });
  });
}
