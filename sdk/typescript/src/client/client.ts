import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import * as fs from 'fs';

export interface ApiKeyAuth {
  type: 'apiKey';
  token: string;
}

export interface MtlsAuth {
  type: 'mtls';
  cert: Buffer;
  key: Buffer;
  ca: Buffer;
}

export interface AgentCageConfig {
  address: string;
  auth?: ApiKeyAuth | MtlsAuth;
  insecure?: boolean;
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

export function createChannel(config: AgentCageConfig): grpc.Channel {
  let creds: grpc.ChannelCredentials;

  if (config.insecure || !config.auth) {
    creds = grpc.credentials.createInsecure();
  } else if (config.auth.type === 'mtls') {
    creds = grpc.credentials.createSsl(
      config.auth.ca,
      config.auth.key,
      config.auth.cert,
    );
  } else {
    creds = grpc.credentials.createInsecure();
  }

  return new grpc.Channel(config.address, creds, {});
}

export function createCallCredentials(auth?: ApiKeyAuth): grpc.CallCredentials | undefined {
  if (!auth || auth.type !== 'apiKey') return undefined;
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

  let creds: grpc.ChannelCredentials;
  if (config.insecure || !config.auth) {
    creds = grpc.credentials.createInsecure();
  } else if (config.auth.type === 'mtls') {
    creds = grpc.credentials.createSsl(config.auth.ca, config.auth.key, config.auth.cert);
  } else {
    creds = grpc.credentials.createInsecure();
  }

  const client = new ServiceClass(config.address, creds);

  return client;
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
