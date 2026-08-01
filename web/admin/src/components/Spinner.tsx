import styles from './Spinner.module.css';

/** Состояние ожидания на весь экран или блок. */
export function Spinner({ label = 'Загрузка…' }: { label?: string }) {
  return (
    <div className={styles.wrap} role="status" aria-live="polite" aria-atomic="true">
      {label}
    </div>
  );
}
