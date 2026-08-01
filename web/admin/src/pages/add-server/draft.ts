import type { ProtocolKind } from '@/api/types';
import type { ProtocolSpecBody } from '@/api/endpoints';

/**
 * Состояние мастера. Шаги 1–3 живут целиком на клиенте — единственный
 * сетевой вызов до установки это проверка подключения.
 */
export interface ProtocolDraft {
  kind: ProtocolKind;
  enabled: boolean;
  port: string;
  mtu: string;
  subnetAddress: string;
  siteName: string;
}

export interface Draft {
  step: number;

  // Шаг 1
  name: string;
  host: string;
  sshPort: string;
  geo: string;
  provider: string;
  keyLimit: string;
  note: string;

  // Шаг 2
  authType: 'password' | 'privateKey';
  sshUser: string;
  sshPassword: string;
  sshPrivateKey: string;
  sshKeyPassphrase: string;

  // Шаг 3
  protocols: ProtocolDraft[];
}

/**
 * Значения по умолчанию.
 *
 * Подсети у протоколов семейства WireGuard разные с самого начала: два
 * контейнера в одной подсети конфликтуют по NAT, и оба перестают работать.
 */
export const initialDraft: Draft = {
  step: 1,

  name: '',
  host: '',
  sshPort: '22',
  geo: '',
  provider: '',
  keyLimit: '',
  note: '',

  authType: 'password',
  sshUser: 'root',
  sshPassword: '',
  sshPrivateKey: '',
  sshKeyPassphrase: '',

  protocols: [
    {
      kind: 'awg2',
      enabled: true,
      // Пусто — сервер выберет случайный порт из диапазона 30000–50000.
      // Фиксированный 55424 сам по себе выдаёт Amnezia при сканировании.
      port: '',
      mtu: '1376',
      subnetAddress: '10.8.1.0',
      siteName: '',
    },
    {
      kind: 'wireguard',
      enabled: false,
      port: '',
      mtu: '1420',
      subnetAddress: '10.8.2.0',
      siteName: '',
    },
    {
      kind: 'xray',
      enabled: true,
      port: '443',
      mtu: '',
      subnetAddress: '',
      siteName: 'www.googletagmanager.com',
    },
  ],
};

export type DraftAction =
  | { type: 'set'; field: keyof Draft; value: string }
  | { type: 'step'; step: number }
  | { type: 'toggleProtocol'; kind: ProtocolKind }
  | { type: 'setProtocol'; kind: ProtocolKind; field: keyof ProtocolDraft; value: string };

export function draftReducer(state: Draft, action: DraftAction): Draft {
  switch (action.type) {
    case 'set':
      return { ...state, [action.field]: action.value };

    case 'step':
      return { ...state, step: action.step };

    case 'toggleProtocol':
      return {
        ...state,
        protocols: state.protocols.map((p) =>
          p.kind === action.kind ? { ...p, enabled: !p.enabled } : p,
        ),
      };

    case 'setProtocol':
      return {
        ...state,
        protocols: state.protocols.map((p) =>
          p.kind === action.kind ? { ...p, [action.field]: action.value } : p,
        ),
      };

    default:
      return state;
  }
}

/** Протоколы, отмеченные к установке, в виде запроса к API. */
export function toProtocolSpecs(draft: Draft): ProtocolSpecBody[] {
  return draft.protocols
    .filter((p) => p.enabled)
    .map((p) => {
      const spec: ProtocolSpecBody = { kind: p.kind };

      // Пустые поля не отправляем: сервер подставит значения по умолчанию,
      // а пустая строка перезаписала бы их.
      if (p.port.trim()) spec.port = p.port.trim();
      if (p.mtu.trim()) spec.mtu = p.mtu.trim();

      if (p.kind === 'xray') {
        if (p.siteName.trim()) spec.siteName = p.siteName.trim();
      } else if (p.subnetAddress.trim()) {
        spec.subnetAddress = p.subnetAddress.trim();
        spec.subnetCidr = '24';
      }

      return spec;
    });
}

/** Порты, занятость которых проверяем перед установкой. */
export function portsToCheck(draft: Draft): string[] {
  return draft.protocols
    .filter((p) => p.enabled && p.port.trim())
    .map((p) => p.port.trim());
}

/** Что мешает перейти с текущего шага дальше. */
export function stepBlocker(draft: Draft): string | null {
  if (draft.step === 1) {
    if (!draft.name.trim()) return 'Укажите имя сервера.';
    if (!draft.host.trim()) return 'Укажите IP-адрес или домен.';
    return null;
  }

  if (draft.step === 2) {
    if (!draft.sshUser.trim()) return 'Укажите пользователя SSH.';
    if (draft.authType === 'password' && !draft.sshPassword) return 'Введите пароль SSH.';
    if (draft.authType === 'privateKey' && !draft.sshPrivateKey.trim())
      return 'Вставьте приватный ключ.';
    return null;
  }

  if (draft.step === 3) {
    const enabled = draft.protocols.filter((p) => p.enabled);
    if (enabled.length === 0) return 'Выберите хотя бы один протокол.';

    const subnets = enabled
      .filter((p) => p.kind !== 'xray')
      .map((p) => p.subnetAddress.trim());

    if (new Set(subnets).size !== subnets.length)
      return 'У протоколов WireGuard должны быть разные подсети.';

    return null;
  }

  return null;
}
