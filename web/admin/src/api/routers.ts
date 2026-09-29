import { api } from './client';

export type RouterState = 'waiting' | 'online' | 'offline' | 'unknown' | 'setup' | 'paused';
export interface RouterMonitor {
  id: string; name: string; userId: string; userName: string | null; telegramId: number | null;
  recipientAvailable: boolean; serverId: string; serverName: string | null; protocolId: string;
  keyId: string; provisionEventId: string; paused: boolean; notificationsEnabled: boolean;
  offlineAfterSeconds: number; deliveryGeneration: number; state: RouterState; stateSince: string;
  lastCheckedAt: string | null; lastHandshakeAt: string | null; outageStartedAt: string | null;
  detail: string | null; createdAt: string;
}
export interface RouterHistory {
  id: string; at: string; state: RouterState | 'test'; detail: string | null;
  lastHandshakeAt: string | null; outageSeconds: number | null; deliveryStatus: string;
  deliveryError: string | null; sentAt: string | null;
}
export interface RouterOptions {
  users: { id: string; name: string; telegramId: number }[];
  servers: { id: string; name: string; protocols: { id: string; name: string }[] }[];
}
export interface RouterSettings {
  name: string; userId: string; paused: boolean; notificationsEnabled: boolean;
  offlineAfterSeconds: number; deliveryGeneration: number;
}
export const routerKeys = { all: ['routers'] as const, list: ['routers', 'list'] as const,
  options: ['routers', 'options'] as const, detail: (id: string) => ['routers', id] as const,
  history: (id: string) => ['routers', id, 'history'] as const };
export const routersApi = {
  list: () => api.get<RouterMonitor[]>('/routers'),
  options: () => api.get<RouterOptions>('/routers/options'),
  get: (id: string) => api.get<RouterMonitor>(`/routers/${id}`),
  history: (id: string) => api.get<RouterHistory[]>(`/routers/${id}/history`),
  create: (body: { name: string; userId: string; serverId: string; protocolId: string }) => api.post<{ id: string }>('/routers', body),
  update: (id: string, body: RouterSettings) => api.put<void>(`/routers/${id}`, body),
  archive: (id: string) => api.delete<void>(`/routers/${id}`),
  test: (id: string) => api.post<void>(`/routers/${id}/test`),
  config: (id: string) => api.get<{ fileName: string; content: string }>(`/routers/${id}/config`),
};
