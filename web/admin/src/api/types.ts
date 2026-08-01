/**
 * Типы ответов API. Зеркалят DTO бэкенда из AmneziaKeyService.Core/DTOs.
 *
 * Написаны руками, а не сгенерированы: набор небольшой и стабильный,
 * а генератор добавил бы артефакт сборки, который надо синхронизировать.
 * Если расхождения станут реальной проблемой — перейти на openapi-typescript
 * с проверкой в CI, что регенерация не даёт диффа.
 */

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

// ── Авторизация ────────────────────────────────────────────────────────────

export type UserRole = 'owner' | 'admin' | 'operator' | 'viewer' | 'client';
export type UserStatus = 'active' | 'restricted' | 'blocked';

export interface Me {
  id: string;
  username: string;
  displayName: string | null;
  role: UserRole;
  status: UserStatus;
  permissions: string[];
}

export interface LoginResponse {
  token: string | null;
  user: Me;
}

// ── Серверы ────────────────────────────────────────────────────────────────

export type ServerStatus = 'ok' | 'setup' | 'offline' | 'error';
export type ProtocolKind = 'awg2' | 'awg' | 'wireguard' | 'xray';
export type ProtocolState = 'installed' | 'installing' | 'failed' | 'absent';
export type SshAuthType = 'password' | 'privateKey' | 'agent';

export interface ProtocolSummary {
  id: string;
  kind: ProtocolKind;
  displayName: string;
  port: string;
  state: ProtocolState;
}

export interface ServerListItem {
  id: string;
  name: string;
  host: string;
  geo: string | null;
  provider: string | null;
  sshPort: number;
  sshAuthType: SshAuthType;
  protocols: ProtocolSummary[];
  keysCount: number;
  loadPercent: number | null;
  trafficBytes: number;
  status: ServerStatus;
}

export interface SshInfo {
  port: number;
  user: string;
  authType: SshAuthType;
  hasPassword: boolean;
  hasPrivateKey: boolean;
  keyType: string | null;
  hostFingerprint: string | null;
}

export interface Obfuscation {
  jc: string;
  jmin: string;
  jmax: string;
  mtu: string;
}

export interface WgInfo {
  interfaceName: string;
  binary: string;
  subnetAddress: string;
  subnetCidr: string;
  lastKnownPeerIp: string | null;
  obfuscation: Obfuscation | null;
}

export interface XrayInfo {
  siteName: string;
  publicKey: string | null;
  shortId: string | null;
}

export interface ProtocolDetail {
  id: string;
  kind: ProtocolKind;
  displayName: string;
  containerName: string;
  containerVersion: string | null;
  enabled: boolean;
  state: ProtocolState;
  port: string;
  transportProto: string;
  mtu: string | null;
  isCached: boolean;
  wg: WgInfo | null;
  xray: XrayInfo | null;
  installedAt: string | null;
  lastSyncedAt: string | null;
}

export interface ServerHealth {
  lastCheckAt: string | null;
  online: boolean;
  uptimeSince: string | null;
  loadPercent: number | null;
  memPercent: number | null;
  diskPercent: number | null;
  dockerVersion: string | null;
  kernel: string | null;
}

export interface ServerKpi {
  uptime30dPercent: number | null;
  keysActive: number;
  trafficBytes: number;
}

export interface ServerDetail {
  id: string;
  name: string;
  host: string;
  geo: string | null;
  provider: string | null;
  note: string | null;
  keyLimit: number | null;
  status: ServerStatus;
  dns1: string;
  dns2: string;
  ssh: SshInfo;
  protocols: ProtocolDetail[];
  defaultProtocolId: string | null;
  health: ServerHealth | null;
  kpi: ServerKpi;
  /** Peer-ы на узле, которым не соответствует ни один выданный ключ. */
  orphanPeerCount: number;
  reconciledAt: string | null;
  createdAt: string;
  updatedAt: string | null;
}

// ── Ключи ──────────────────────────────────────────────────────────────────

export type KeyStatus = 'active' | 'revoked' | 'expired' | 'suspended' | 'pendingRevoke';
export type KeySource = 'telegram' | 'panel' | 'api';

export interface KeyListItem {
  id: string;
  shortId: string;
  ownerName: string | null;
  deviceName: string | null;
  label: string | null;
  serverId: string;
  serverName: string | null;
  protocolId: string | null;
  protocolKind: ProtocolKind | null;
  protocolDisplayName: string | null;
  assignedIp: string | null;
  issuedAt: string;
  expiresAt: string | null;
  trafficBytes: number;
  trafficLimitBytes: number | null;
  lastHandshakeAt: string | null;
  online: boolean;
  status: KeyStatus;
  source: KeySource;
}

/**
 * Ответ на выдачу ключа. Единственный момент, когда секреты приходят наружу:
 * приватный ключ входит в vpnUri и в текст конфига. Повторно панель их
 * не покажет — хранить нечего.
 */
export interface IssuedKey {
  key: KeyListItem;
  vpnUri: string;
  fileName: string;
  fileContent: string;
}

/** Принятая в очередь заявка на операцию с ключом. */
export interface EventAccepted {
  eventId: string;
  keyId: string;
}

/** Состояние фоновой операции, которое панель опрашивает до завершения. */
export interface DomainEvent {
  id: string;
  type: string;
  status: 'pending' | 'claimed' | 'succeeded' | 'failed' | 'canceled';
  error: string | null;
}

/** Секретная часть уже созданного ключа. */
export interface KeySecret {
  vpnUri: string;
  fileName: string;
  fileContent: string;
}

export interface KeyDetail {
  summary: KeyListItem;
  clientPubKey: string | null;
  xrayClientId: string | null;
  userId: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  rxBytes: number;
  txBytes: number;
  lastSeenAt: string | null;
}

// ── Установка ──────────────────────────────────────────────────────────────

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled';
export type StepStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped';

export interface InstallStep {
  code: string;
  title: string;
  status: StepStatus;
  detail: string | null;
  message: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface Job {
  id: string;
  serverId: string;
  kind: string;
  status: JobStatus;
  currentStepCode: string | null;
  progressPercent: number;
  steps: InstallStep[];
  logSeq: number;
  cancelRequested: boolean;
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface JobLogEntry {
  seq: number;
  at: string;
  stepCode: string | null;
  level: AuditLevel;
  text: string;
}

export interface JobLog {
  entries: JobLogEntry[];
  nextSeq: number;
  done: boolean;
}

export interface JobAccepted {
  serverId: string;
  jobId: string;
}

export interface ConnectionTest {
  ok: boolean;
  kernel: string | null;
  dockerVersion: string | null;
  sudoAvailable: boolean;
  hostFingerprint: string | null;
  busyPorts: string[];
  error: string | null;
}

// ── Пользователи ───────────────────────────────────────────────────────────

export interface UserListItem {
  id: string;
  username: string;
  displayName: string | null;
  contact: string | null;
  telegramId: number | null;
  role: UserRole;
  status: UserStatus;
  keysCount: number;
  createdAt: string;
}

export interface PassCode {
  id: string;
  code: string;
  isUsed: boolean;
  isRevoked: boolean;
  usedByUserId: string | null;
  usedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

// ── Журнал ─────────────────────────────────────────────────────────────────

export type AuditLevel = 'info' | 'warn' | 'error';

export interface AuditEntry {
  id: string;
  at: string;
  level: AuditLevel;
  event: string;
  message: string;
  actorName: string | null;
  targetType: string | null;
  targetId: string | null;
  targetName: string | null;
}

// ── Сводка ─────────────────────────────────────────────────────────────────

export interface AttentionItem {
  kind: string;
  message: string;
  count: number;
}

export interface DashboardSummary {
  serversOk: number;
  serversTotal: number;
  keysActive: number;
  keysTotal: number;
  trafficMonthBytes: number;
  attention: { total: number; items: AttentionItem[] };
  navBadges: { servers: number; keys: number; users: number; logs: number };
  lastSyncAt: string | null;
  appVersion: string;
}

// ── Настройки ──────────────────────────────────────────────────────────────

export interface PanelSettings {
  defaultExpiryDays: number | null;
  deviceLimitPerClient: number | null;
  defaultProtocolKind: ProtocolKind;
  defaultTrafficLimitBytes: number | null;
  maskSecrets: boolean;
  twoFactorEnabled: boolean;
  alertTelegramChat: string | null;
  updatedAt: string | null;
}
