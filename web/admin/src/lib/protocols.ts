import type { ProtocolKind } from '@/api/types';

/**
 * Отображаемые названия протоколов. Дублируют ProtocolKinds.DisplayName
 * на бэкенде — нужны там, где сервер отдаёт только код (например, в настройках).
 */
export const ProtocolDisplay: Record<ProtocolKind, string> = {
  awg2: 'AmneziaWG',
  awg: 'AmneziaWG',
  wireguard: 'WireGuard',
  xray: 'VLESS Reality',
};

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
