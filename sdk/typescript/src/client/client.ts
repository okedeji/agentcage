import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';

export interface ApiKeyAuth {
  type: 'apiKey';
  token: string;
}

export interface AgentCageConfig {
  address: string;
  auth?: ApiKeyAuth;
  insecure?: boolean;
  /** CA certificate PEM bytes for server verification.
   *  If not provided, connect() fetches it from the server (trust-on-first-use). */
  caCert?: Buffer;
}

const PROTO_DIR = path.resolve(__dirname, '../../proto');

function loadProto(filename: string): grpc.GrpcObject {
  const protoPath = path.join(PROTO_DIR, filename);
  const packageDef = protoLoader.loadSync(protoPath, {
    keepCase: false,
    longs: Number,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_DIR],
  });
  return grpc.loadPackageDefinition(packageDef);
}

export function buildCredentials(config: AgentCageConfig): grpc.ChannelCredentials {
  if (config.insecure) {
    return grpc.credentials.createInsecure();
  }
  if (config.caCert) {
    return grpc.credentials.createSsl(config.caCert);
  }
  // No CA cert yet — skip verification for initial connect.
  // connect() will fetch the CA and rebuild with verification.
  return grpc.credentials.createSsl();
}

export function createCallCredentials(auth?: ApiKeyAuth): grpc.CallCredentials | undefined {
  if (!auth) return undefined;
  return grpc.credentials.createFromMetadataGenerator((_, cb) => {
    const metadata = new grpc.Metadata();
    metadata.set('authorization', `Bearer ${auth.token}`);
    cb(null, metadata);
  });
}

export function getServiceClient(
  protoFile: string,
  packagePath: string,
  serviceName: string,
  config: AgentCageConfig,
): grpc.Client {
  const proto = loadProto(protoFile);
  const parts = packagePath.split('.');
  let pkg: any = proto;
  for (const p of parts) {
    pkg = pkg[p];
  }
  const ServiceClass = pkg[serviceName] as typeof grpc.Client;
  const creds = buildCredentials(config);
  return new ServiceClass(config.address, creds);
}

export function callUnary<TReq, TResp>(
  client: grpc.Client,
  method: string,
  request: TReq,
  callCreds?: grpc.CallCredentials,
): Promise<TResp> {
  return new Promise((resolve, reject) => {
    const options: grpc.CallOptions = {};
    if (callCreds) {
      options.credentials = callCreds;
    }
    (client as any)[method](request, options, (err: grpc.ServiceError | null, resp: TResp) => {
      if (err) reject(err);
      else resolve(resp);
    });
  });
}
