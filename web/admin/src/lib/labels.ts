import type {
  AuditLevel,
  KeyStatus,
  ProtocolState,
  ServerStatus,
  SubscriptionRevokeReason,
  SubscriptionSource,
  SubscriptionStatus,
  UserRole,
  UserStatus,
} from '@/api/types';

/**
 * Подписи и оформление статусов.
 *
 * Дизайн-система намеренно одноцветная: зелёного и жёлтого в ней нет.
 * Семантика в макете такая — нейтральный тег означает норму, контурный
 * переходное состояние, акцентный (красный) проблему.
 */
export type TagTone = 'neutral' | 'outline' | 'accent';

export const serverStatus: Record<ServerStatus, { label: string; tone: TagTone }> = {
  empty: { label: 'без протоколов', tone: 'outline' },
  ok: { label: 'работает', tone: 'neutral' },
  setup: { label: 'установка', tone: 'outline' },
  offline: { label: 'недоступен', tone: 'accent' },
  error: { label: 'ошибка', tone: 'accent' },
};

export const protocolState: Record<ProtocolState, { label: string; tone: TagTone }> = {
  installed: { label: 'работает', tone: 'neutral' },
  installing: { label: 'разворачивается', tone: 'outline' },
  failed: { label: 'ошибка', tone: 'accent' },
  absent: { label: 'не установлен', tone: 'outline' },
};

export const keyStatus: Record<KeyStatus, { label: string; tone: TagTone }> = {
  active: { label: 'активен', tone: 'neutral' },
  revoked: { label: 'отозван', tone: 'accent' },
  expired: { label: 'истёк', tone: 'outline' },
  suspended: { label: 'приостановлен', tone: 'outline' },
  pendingRevoke: { label: 'отзывается', tone: 'outline' },
  detached: { label: 'узел удалён', tone: 'outline' },
};

export const userStatus: Record<UserStatus, { label: string; tone: TagTone }> = {
  active: { label: 'активен', tone: 'neutral' },
  restricted: { label: 'ограничен', tone: 'outline' },
  blocked: { label: 'заблокирован', tone: 'accent' },
};

export const auditLevel: Record<AuditLevel, { label: string; tone: TagTone }> = {
  info: { label: 'info', tone: 'neutral' },
  warn: { label: 'внимание', tone: 'outline' },
  error: { label: 'ошибка', tone: 'accent' },
};

export const userRole: Record<UserRole, string> = {
  owner: 'владелец',
  admin: 'администратор',
  operator: 'оператор',
  viewer: 'наблюдатель',
  client: 'клиент',
};

/** Тип SSH-доступа для колонки «IP · SSH». */
export const sshAuthType: Record<string, string> = {
  password: 'пароль',
  privateKey: 'SSH-ключ',
  agent: 'SSH-агент',
};

const subscriptionRevokeReason: Record<SubscriptionRevokeReason, { label: string; tone: TagTone }> = {
  expired: { label: 'отозвана · истёк срок', tone: 'outline' },
  quota: { label: 'отозвана · квота', tone: 'accent' },
  manual: { label: 'отозвана · вручную', tone: 'accent' },
};

/**
 * Статус подписки с причиной отзыва: «квота» и «вручную» заметнее «срока» — первое требует
 * решения оператора, второе штатно.
 */
export function subscriptionStatus(
  status: SubscriptionStatus,
  reason: SubscriptionRevokeReason | null,
): { label: string; tone: TagTone } {
  if (status === 'active') return { label: 'активна', tone: 'neutral' };
  return (reason && subscriptionRevokeReason[reason]) || { label: 'отозвана', tone: 'accent' };
}

export const subscriptionSource: Record<SubscriptionSource, string> = {
  telegram: 'Telegram',
  panel: 'панель',
};
