import type { ProtocolKind, XCoreRole } from '@/api/types';

/**
 * Отображаемые названия протоколов. Дублируют ProtocolKinds.DisplayName
 * на бэкенде — нужны там, где сервер отдаёт только код (например, в настройках).
 */
export const ProtocolDisplay: Record<ProtocolKind, string> = {
  awg3: 'AmneziaWG 3.1',
  awg2: 'AmneziaWG 2.0',
  awg: 'AmneziaWG 1.0',
  wireguard: 'WireGuard',
  xray: 'VLESS Reality',
  xcore: 'Xray (подписки)',
};

/** Название вида в форме установки: оператору важнее назначение, чем имя ядра. */
export const XCORE_INSTALL_LABEL = 'Xray для подписок Happ';

export const XCORE_ROLE_LABEL: Record<XCoreRole, string> = {
  exit: 'Выход (за рубежом)',
  entry: 'Вход (в РФ)',
};

export const XCORE_ENTRY_HINT =
  'Вход принимает клиентов в РФ и передаёт трафик на выходы; российские сайты идут напрямую с его IP';

/**
 * Есть ли по протоколу пер-клиентская статистика трафика.
 *
 * У Xray её нет: в server.json, который генерирует upstream, отсутствует блок
 * stats/api, а расходиться с upstream-конфигом ради счётчиков мы не стали.
 * Ноль в такой ячейке означал бы «не пользуются», поэтому рисуем прочерк
 * и объясняем причину в подсказке.
 */
export function hasTrafficStats(kind: ProtocolKind | null): boolean {
  return kind !== null && kind !== 'xray';
}

export const NO_TRAFFIC_STATS_HINT =
  'Учёт трафика по клиентам недоступен для VLESS Reality';
