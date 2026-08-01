import type { ReactNode } from 'react';
import { cx } from './Btn';
import styles from './Misc.module.css';

/**
 * Полоса загрузки узла. Выше 60% окрашивается акцентом — единственный
 * способ показать тревогу в одноцветной системе.
 */
export function LoadBar({ percent }: { percent: number | null }) {
  if (percent === null) return <span className={styles.dash}>—</span>;

  const clamped = Math.max(0, Math.min(100, percent));

  return (
    <span className={styles.loadWrap}>
      <span className={styles.loadTrack}>
        <span
          className={cx(styles.loadFill, clamped > 60 && styles.loadFillHigh)}
          style={{ inlineSize: `${clamped}%` }}
        />
      </span>
      <span className={styles.loadValue}>{Math.round(clamped)}%</span>
    </span>
  );
}

/** Двухстрочная ячейка: значение и приглушённое пояснение под ним. */
export function Stacked({ primary, secondary }: { primary: ReactNode; secondary?: ReactNode }) {
  return (
    <span className={styles.stacked}>
      <span className={styles.stackedPrimary}>{primary}</span>
      {secondary ? <span className={styles.stackedSecondary}>{secondary}</span> : null}
    </span>
  );
}

/** Скрытый секрет. Панель не может показать его повторно — только заменить. */
export function MaskedValue({ hint }: { hint?: string }) {
  return (
    <span className={cx(styles.masked, 'mono')}>
      •••••••••••••••• {hint ?? 'скрыт'}
    </span>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className={styles.empty} role="status">
      <div className={styles.emptyTitle}>{title}</div>
      {hint ? <p className={styles.emptyHint}>{hint}</p> : null}
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className={styles.error} role="alert">
      <span>{message}</span>
      {onRetry ? <button type="button" className="btn btn-ghost" onClick={onRetry}>Повторить</button> : null}
    </div>
  );
}

/** Секционный заголовок дизайн-системы: h6 уже заглавный и с трекингом. */
export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className={styles.sectionTitle}>
      <h6 className={styles.sectionHeading}>{children}</h6>
      {action}
    </div>
  );
}

/** Строка «метка — значение» в карточке параметров. */
export function DefRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className={styles.defRow}>
      <span className={styles.defLabel}>{label}</span>
      <span className={styles.defValue}>{children}</span>
    </div>
  );
}

/** Кнопка «Показать ещё» под длинным списком. В макете пагинации нет,
 *  но 248 ключей её требуют — это наименее заметное дополнение. */
export function LoadMore({ onClick, remaining }: { onClick: () => void; remaining: number }) {
  return (
    <div className={styles.loadMore}>
      <button type="button" className="btn btn-secondary" onClick={onClick}>
        Показать ещё {remaining > 0 ? `(${remaining})` : ''}
      </button>
    </div>
  );
}
