import { api } from './client';
import type {
  AuditEntry,
  ConnectionTest,
  DashboardSummary,
  DomainEvent,
  EventAccepted,
  Job,
  JobAccepted,
  JobLog,
  KeyDetail,
  KeyListItem,
  KeySecret,
  LoginResponse,
  Me,
  Paged,
  PanelSettings,
  ProtocolKind,
  XCoreRole,
  ServerDetail,
  ServerListItem,
  SubscriptionDetail,
  SubscriptionLink,
  SubscriptionListItem,
  UserListItem,
  PassCode,
  NotificationAudience,
  NotificationCampaign,
} from './types';

export interface ListParams {
  search?: string;
  page?: number;
  pageSize?: number;
}

export const auth = {
  login: (username: string, password: string) =>
    api.post<LoginResponse>('/auth/login', { username, password }),

  logout: () => api.post<void>('/auth/logout'),

  me: (signal?: AbortSignal) => api.get<Me>('/auth/me', undefined, signal),
};

export const dashboard = {
  summary: () => api.get<DashboardSummary>('/dashboard/summary'),
};

export interface ServerListParams extends ListParams {
  protocol?: string;
  status?: string;
}

export const servers = {
  discover: (body: TestConnectionBody) => api.post<ServerDiscovery>('/servers/discover', body),
  importExisting: (body: ImportServerBody) => api.post<ServerDetail>('/servers/import', body),
  addProtocol: (id: string, body: ProtocolSpecBody) => api.post<JobAccepted>(`/servers/${id}/protocols`, body),
  setProtocolEnabled: (id: string, protocolId: string, enabled: boolean) =>
    api.put<void>(`/servers/${id}/protocols/${protocolId}/availability`, { enabled }),
  updateXCoreSettings: (id: string, protocolId: string, body: XCoreSettingsBody) =>
    api.put<void>(`/servers/${id}/protocols/${protocolId}/xcore`, body),
  /** «Обновить списки сейчас»: ставит обновление в очередь worker, ответ 202 без тела. */
  updateXCoreRfLists: (id: string, protocolId: string) =>
    api.post<void>(`/servers/${id}/protocols/${protocolId}/xcore/rf-lists/update`),

  list: (params: ServerListParams = {}) =>
    api.get<Paged<ServerListItem>>('/servers', { ...params }),

  detail: (id: string) => api.get<ServerDetail>(`/servers/${id}`),

  keys: (id: string, params: ListParams = {}) =>
    api.get<Paged<KeyListItem>>(`/servers/${id}/keys`, { ...params }),

  refresh: (id: string) => api.post<ServerDetail>(`/servers/${id}/refresh`),

  delete: (id: string, confirmationName: string, forgetKeys = false) => api.delete<JobAccepted>(`/servers/${id}`, { confirmationName, forgetKeys }),
  cleanup: (id: string, confirmationName: string) => api.post<JobAccepted>(`/servers/${id}/cleanup`, { confirmationName }),

  install: (body: CreateServerBody) => api.post<JobAccepted>('/servers/install', body),

  testConnection: (body: TestConnectionBody) =>
    api.post<ConnectionTest>('/servers/test-connection', body),
};

export interface ProtocolSpecBody {
  kind: ProtocolKind;
  port?: string;
  mtu?: string;
  subnetAddress?: string;
  subnetCidr?: string;
  siteName?: string;
  /** Домен узла xcore (обязателен для него). */
  domain?: string;
  /** Роль xcore; не передана — сервер ставит «выход». */
  role?: XCoreRole;
}

/**
 * Настройки xcore (PUT). Поля входа выходу передавать нельзя — сервер ответит отказом. У входа домен подписки
 * передаётся всегда: null снимает его.
 */
export interface XCoreSettingsBody {
  title: string | null;
  sortOrder: number;
  subscriptionEnabled: boolean;
  ruDirect?: boolean;
  directDomains?: string[];
  proxyDomains?: string[];
  subscriptionHost?: string | null;
  /** Не передано — без изменений. true создаёт ключи на узле (нужен доступ по SSH), false стирает их. */
  vlessEncryption?: boolean;
}

export interface DiscoveredProtocol {
  kind: ProtocolKind;
  displayName: string;
  containerName: string;
  port: string | null;
  subnet: string | null;
  peerCount: number;
  canImport: boolean;
  error: string | null;
}

export interface ServerDiscovery {
  revision: string;
  protocols: DiscoveredProtocol[];
  warnings: string[];
}

export interface ImportServerBody extends Omit<CreateServerBody, 'protocols'> {
  revision: string;
  containers: string[];
}

export interface CreateServerBody {
  host: string;
  name: string;
  geo?: string;
  provider?: string;
  note?: string;
  keyLimit?: number | null;
  sshPort: number;
  sshUser: string;
  sshPassword?: string;
  sshPrivateKey?: string;
  sshKeyPassphrase?: string;
  protocols: ProtocolSpecBody[];
}

export interface TestConnectionBody {
  host: string;
  sshPort: number;
  sshUser: string;
  sshPassword?: string;
  sshPrivateKey?: string;
  sshKeyPassphrase?: string;
  ports?: string[];
}

export const jobs = {
  get: (id: string) => api.get<Job>(`/jobs/${id}`),

  log: (id: string, after: number) =>
    api.get<JobLog>(`/jobs/${id}/log`, { after, limit: 200 }),

  cancel: (id: string) => api.post<Job>(`/jobs/${id}/cancel`),
};

export interface KeyListParams extends ListParams {
  status?: string;
  serverId?: string;
  protocol?: string;
  userId?: string;
}

export interface IssueKeyBody {
  serverId: string;
  protocolId?: string;
  userId?: string;
  ownerName?: string;
  contact?: string;
  deviceName?: string;
  label?: string;
  expiryDays?: number | null;
  trafficLimitBytes?: number | null;
}

export const keys = {
  list: (params: KeyListParams = {}) => api.get<Paged<KeyListItem>>('/keys', { ...params }),

  detail: (id: string) => api.get<KeyDetail>(`/keys/${id}`),

  issue: (body: IssueKeyBody) => api.post<EventAccepted>('/keys', body),

  secret: (id: string) => api.get<KeySecret>(`/keys/${id}/secret`),

  revoke: (id: string, comment?: string) =>
    api.post<KeyListItem>(`/keys/${id}/revoke`, { comment }),

  /** Ссылка на скачивание. Идёт напрямую браузером — кука уедет сама. */
  downloadUrl: (id: string) => `/api/keys/${id}/download?format=conf`,
};

export interface SubscriptionListParams extends ListParams {
  status?: string;
  userId?: string;
}

export interface CreateSubscriptionBody {
  userId: string;
  /** Не передано — из настроек панели, 0 — бессрочно. */
  expiryDays?: number;
  /** Не передано — из настроек панели, 0 — без ограничения. */
  trafficLimitBytes?: number;
}

/** Новые границы заменяют прежние целиком: null снимает ограничение. */
export interface UpdateSubscriptionLimitsBody {
  expiresAt: string | null;
  trafficLimitBytes: number | null;
}

export const subscriptions = {
  list: (params: SubscriptionListParams = {}) =>
    api.get<Paged<SubscriptionListItem>>('/subscriptions', { ...params }),

  detail: (id: string) => api.get<SubscriptionDetail>(`/subscriptions/${id}`),

  /** Ссылка подписки — секрет, отвечает с no-store. Запрашивается только по действию оператора. */
  link: (id: string) => api.get<SubscriptionLink>(`/subscriptions/${id}/link`),

  create: (body: CreateSubscriptionBody) => api.post<SubscriptionDetail>('/subscriptions', body),

  revoke: (id: string) => api.post<SubscriptionDetail>(`/subscriptions/${id}/revoke`),

  /** Меняет токен и UUID: прежняя ссылка и все настроенные по ней устройства перестают работать. */
  regenerate: (id: string) => api.post<SubscriptionDetail>(`/subscriptions/${id}/regenerate`),

  updateLimits: (id: string, body: UpdateSubscriptionLimitsBody) =>
    api.put<SubscriptionDetail>(`/subscriptions/${id}/limits`, body),
};

export const events = {
  get: (id: string) => api.get<DomainEvent>(`/events/${id}`),
};

export interface UserListParams extends ListParams {
  status?: string;
  role?: string;
}

export const users = {
  list: (params: UserListParams = {}) => api.get<Paged<UserListItem>>('/users', { ...params }),
  get: (id: string) => api.get<UserListItem>(`/users/${id}`),
  create: (body: CreatePanelUserBody) => api.post<UserListItem>('/users', body),
  update: (id: string, body: UpdatePanelUserBody) => api.put<UserListItem>(`/users/${id}`, body),
  block: (id: string) => api.post<UserListItem>(`/users/${id}/block`),
  unblock: (id: string) => api.post<UserListItem>(`/users/${id}/unblock`),
  resetPassword: (id: string, password: string) => api.post<void>(`/users/${id}/reset-password`, { password }),
  deactivate: (id: string) => api.delete<void>(`/users/${id}`),
};

export interface CreatePanelUserBody {
  username: string;
  password: string;
  displayName?: string;
  contact?: string;
  role: 'admin' | 'operator' | 'viewer';
}

export interface UpdatePanelUserBody {
  displayName?: string | null;
  contact?: string | null;
  role: UserListItem['role'];
  status: UserListItem['status'];
  /** Required when a client is promoted to a panel role. */
  password?: string;
}

export const passcodes = {
  list: () => api.get<PassCode[]>('/passcodes'),
  create: (code: string) => api.post<PassCode>('/passcodes', { code }),
  revoke: (id: string) => api.delete<void>(`/passcodes/${id}`),
};

export interface NotificationListParams extends ListParams {
  status?: string;
}

export interface CreateNotificationBody {
  title?: string;
  text: string;
  disableNotification: boolean;
}

export const notifications = {
  list: (params: NotificationListParams = {}) =>
    api.get<Paged<NotificationCampaign>>('/notifications', { ...params }),
  audience: () => api.get<NotificationAudience>('/notifications/audience'),
  get: (id: string) => api.get<NotificationCampaign>(`/notifications/${id}`),
  create: (body: CreateNotificationBody) =>
    api.post<NotificationCampaign>('/notifications', body),
  cancel: (id: string) =>
    api.post<NotificationCampaign>(`/notifications/${id}/cancel`),
};

export interface LogListParams extends ListParams {
  level?: string;
  targetType?: string;
  targetId?: string;
}

export const logs = {
  list: (params: LogListParams = {}) => api.get<Paged<AuditEntry>>('/logs', { ...params }),
};

export const settings = {
  get: () => api.get<PanelSettings>('/settings'),
  update: (body: UpdatePanelSettingsBody) => api.put<PanelSettings>('/settings', body),
};

/** Только параметры, которые сейчас применяются при выдаче новых ключей. */
export interface UpdatePanelSettingsBody {
  defaultExpiryDays: number | null;
  defaultTrafficLimitBytes: number | null;
}
