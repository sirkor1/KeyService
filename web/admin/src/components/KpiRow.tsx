import { cx } from './Btn';
import styles from './KpiRow.module.css';

export interface KpiCell {
  label: string;
  value: string;
  /** Акцентная подача — как «Требуют внимания» в макете. */
  accent?: boolean;
}

/**
 * Ряд равных плиток с вертикальными линейками между ними —
 * основной приём дизайн-системы: сетка видна, ничего не «плавает».
 */
export function KpiRow({ cells, compact }: { cells: KpiCell[]; compact?: boolean }) {
  return (
    <div className={styles.row}>
      {cells.map((cell) => (
        <div key={cell.label} className={styles.cell}>
          <div className={styles.label}>{cell.label}</div>
          <div
            className={cx(styles.value, compact && styles.valueCompact, cell.accent && styles.accent)}
          >
            {cell.value}
          </div>
        </div>
      ))}
    </div>
  );
}
