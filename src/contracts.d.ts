export type WorkspaceProviderKind = 'docker' | 'kubernetes' | 'apple-container';

export interface KubernetesIngressPolicy {
  ingressClassName: string;
  hostTemplate: string;
  pathTemplate: '/';
  tls: { mode: 'existing-secret'; secretName: string } | { mode: 'cert-manager'; clusterIssuer: string };
  controllerNamespaceSelector: Record<string, string>;
  controllerPodSelector: Record<string, string>;
  annotations: Record<string, string>;
}

export type WorkspaceEgressPolicy =
  | { mode: 'managed'; gatewayImage: string; preset: 'restricted' | 'custom'; gatewayPolicy: { version: 1; allowedDomains: string[]; allowedCIDRs: string[]; allowedPorts: number[] }; dnsCIDRs: string[]; noProxy: string }
  | { mode: 'external'; proxyUrl: string; proxyCIDR?: string; dnsCIDRs: string[]; noProxy: string };

export interface WorkspacePolicyV1 {
  version: 1;
  defaultProvider: WorkspaceProviderKind;
  defaultImage: string;
  allowedImages: string[];
  requirePinnedImage: true;
  egress: WorkspaceEgressPolicy;
  credentials: { modelAuth: 'none' | 'explicit-opencode-auth-content' };
  retention: { preserveOnDelete: boolean };
  kubernetes: { context?: string; namespace: string; connectivity: 'port-forward' | 'ingress'; ingress?: KubernetesIngressPolicy; networkPolicy: 'default-deny'; [key: string]: unknown };
  docker: Record<string, unknown>;
  appleContainer: Record<string, unknown>;
}

export interface WorkspaceMetadataV1 {
  version: 1;
  provider: WorkspaceProviderKind;
  controlPlaneWorkspaceID: string;
  originalControlPlaneWorkspaceID: string;
  providerResourceID: string;
  projectID: string;
  runtimeLayoutVersion: 1;
  createdAt: string;
  imageDigest: string;
  resourceRefs: Readonly<Record<string, string | number>>;
  authRef: string;
  policyFingerprint: string;
}

export interface ProviderValidation {
  provider: WorkspaceProviderKind;
  available: boolean;
  diagnostics: string[];
}

export interface ProviderDiscoveryResult {
  projectID: string;
  workspaces: unknown[];
  failures: Array<{ provider: WorkspaceProviderKind; message: string; code?: string }>;
  completeProviders: WorkspaceProviderKind[];
}

export interface CleanupResult {
  ok: boolean;
  remainingResources: string[];
  retainedResources?: string[];
  diagnostics: string[];
}

export interface WorkspaceExportBlob {
  hash: string;
  size: number;
  contentBase64: string;
}

export interface WorkspaceExportFile {
  id: string;
  kind: 'add' | 'modify' | 'delete' | 'rename' | 'mode';
  oldPath?: string;
  newPath?: string;
  binary: boolean;
  oldMode?: number;
  newMode?: number;
  baselineHash?: string;
  resultHash?: string;
  baselineBlob?: string;
  resultBlob?: string;
  symlinkTarget?: string;
  text?: string;
  textHunks?: Array<{ id: string; oldStart: number; oldCount: number; newStart: number; newCount: number; removed: string[]; added: string[]; contextHash: string }>;
}

export interface WorkspaceExportArtifactV1 {
  version: 1;
  id: string;
  controlPlaneWorkspaceID: string;
  providerResourceID: string;
  projectID: string;
  provider: WorkspaceProviderKind;
  baselineGeneration: string;
  targetDirectory: string;
  createdAt: string;
  expiresAt: string;
  integrityHash: string;
  files: WorkspaceExportFile[];
  blobs: WorkspaceExportBlob[];
}

export interface CredentialRotationRequest {
  rotateEndpointToken?: boolean;
  modelAuth?: Record<string, unknown> | string | null;
}

export interface ExportSink {
  write(chunk: string, callback: (error?: Error | null) => void): unknown;
}

export interface StreamedWorkspaceExportReceipt {
  id: string;
  integrityHash: string;
  streamed: true;
}

export interface WorkspaceProviderOperations {
  validateProvider(provider: WorkspaceProviderKind): Promise<ProviderValidation>;
  discoverProject(projectID: string): Promise<ProviderDiscoveryResult>;
  inspectWorkspace(workspace: unknown): Promise<unknown>;
  cleanupWorkspace(workspace: unknown): Promise<CleanupResult>;
  reconcileWorkspace(workspace: unknown): Promise<unknown>;
  rotateWorkspaceCredentials(workspace: unknown, request: CredentialRotationRequest): Promise<{ rotatedEndpointToken: boolean; modelAuth: 'configured' | 'revoked' }>;
  exportWorkspace(workspace: unknown): Promise<WorkspaceExportArtifactV1>;
  exportWorkspace(workspace: unknown, sink: ExportSink): Promise<StreamedWorkspaceExportReceipt>;
  adoptWorkspace<T>(workspace: T): Promise<T>;
}

export const WORKSPACE_PROVIDERS: readonly WorkspaceProviderKind[];
export const METADATA_VERSION: 1;
export const RUNTIME_LAYOUT_VERSION: 1;
export function parseProviderKind(value: unknown): WorkspaceProviderKind;
export function parseWorkspaceRecord<T>(value: T): T;
export function parseWorkspaceMetadata(value: unknown): WorkspaceMetadataV1;
export function parseWorkspaceExportArtifact(value: unknown): WorkspaceExportArtifactV1;
export function parseEgressPolicy(value: unknown): unknown;
export function parseWorkspacePolicy(value?: unknown): WorkspacePolicyV1;
