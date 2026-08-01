import type { KeyListParams, LogListParams, ServerListParams, UserListParams } from './endpoints';

/**
 * Ключи кеша TanStack Query. Собраны в одном месте, чтобы инвалидация
 * после мутации не промахивалась мимо активного запроса.
 */
export const qk = {
  me: ['me'] as const,
  dashboard: ['dashboard'] as const,

  servers: ['servers'] as const,
  serverList: (params: ServerListParams) => ['servers', 'list', params] as const,
  serverDetail: (id: string) => ['servers', 'detail', id] as const,
  serverKeys: (id: string) => ['servers', 'keys', id] as const,

  keys: ['keys'] as const,
  keyList: (params: KeyListParams) => ['keys', 'list', params] as const,
  keyDetail: (id: string) => ['keys', 'detail', id] as const,

  users: ['users'] as const,
  userList: (params: UserListParams) => ['users', 'list', params] as const,
  userDetail: (id: string) => ['users', 'detail', id] as const,

  passcodes: ['passcodes'] as const,

  logs: ['logs'] as const,
  logList: (params: LogListParams) => ['logs', 'list', params] as const,

  settings: ['settings'] as const,
};
