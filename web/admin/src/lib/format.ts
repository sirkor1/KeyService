/**
 * Форматирование под русскую типографику макета: десятичная запятая,
 * единицы ТБ/ГБ, даты дд.мм.гггг, точка-разделитель между полями.
 */

const BYTE_UNITS = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'] as const;

/** Гигабайт в байтах — квоты вводятся в ГБ, а API принимает байты. */
export const BYTES_IN_GB = 1024 ** 3;

/** «2,8 ТБ». Ноль показываем как «—»: пустая ячейка читается хуже прочерка. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '—';
  if (bytes <= 0) return '—';

  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }

  // Байты и килобайты дробной части не требуют.
  const digits = unit <= 1 ? 0 : value < 10 ? 1 : 0;
  return `${value.toLocaleString('ru-RU', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })} ${BYTE_UNITS[unit]}`;
}

/** «дд.мм.гггг» */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

/** «дд.мм чч:мм» — формат отметок времени в журнале. */
export function formatLogTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';

  const day = date.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' });
  const time = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  return `${day} ${time}`;
}

/** «чч:мм» — время последней синхронизации в подвале меню. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

/** «99,98%» */
export function formatPercent(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined) return '—';
  return `${value.toLocaleString('ru-RU', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })}%`;
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return value.toLocaleString('ru-RU');
}

/** Склонение существительного: 1 ключ, 2 ключа, 5 ключей. */
export function plural(count: number, one: string, few: string, many: string): string {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;

  if (mod100 >= 11 && mod100 <= 14) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

/** Соединяет непустые части точкой-разделителем, как в макете. */
export function joinMeta(...parts: (string | null | undefined)[]): string {
  return parts.filter((p): p is string => Boolean(p && p.trim())).join(' · ');
}

/** Инициалы для квадратного аватара в шапке. */
export function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return '—';
  if (words.length === 1) return words[0]!.slice(0, 2).toUpperCase();
  return (words[0]![0]! + words[1]![0]!).toUpperCase();
}
