import { useState } from 'react';
import type { Job } from '@/api/types';
import { cx } from '@/components/Btn';
import styles from './AddServerPage.module.css';

/** Подписи состояний шага — как в макете. */
const STATUS_LABEL: Record<string, string> = {
  pending: 'ожидает',
  running: 'выполняется',
  done: 'готово',
  failed: 'ошибка',
  skipped: 'пропущен',
};

/**
 * Чеклист установки. Строки берутся из самой задачи, а не из локального
 * списка: набор шагов задаёт сервер, и рассинхронизация была бы незаметной.
 */
export function InstallChecklist({ job }: { job: Job }) {
  return (
    <div className={styles.checklist}>
      {job.steps.map((step) => (
        <div key={step.code} className={styles.checkRow}>
          <span
            className={cx(
              styles.mark,
              step.status === 'done' && styles.markDone,
              step.status === 'failed' && styles.markFailed,
              step.status === 'running' && styles.markRunning,
            )}
            aria-hidden="true"
          >
            {step.status === 'done' ? '✓' : step.status === 'failed' ? '!' : ''}
          </span>

          <span className={styles.checkInfo}>
            <span className={styles.checkTitle}>{step.title}</span>
            {step.detail || step.message ? (
              <span className={cx(styles.checkDetail, step.status === 'failed' && styles.checkError)}>
                {step.message ?? step.detail}
              </span>
            ) : null}
          </span>

          <span className={styles.checkStatus}>{STATUS_LABEL[step.status] ?? step.status}</span>
        </div>
      ))}
    </div>
  );
}

/** Хвост лога установки. Свёрнут по умолчанию — обычно он не нужен. */
export function InstallLog({ lines }: { lines: string[] }) {
  const [open, setOpen] = useState(false);

  if (lines.length === 0) return null;

  return (
    <div className={styles.logBlock}>
      <button type="button" className="btn btn-ghost" onClick={() => setOpen(!open)}>
        {open ? 'Скрыть журнал установки' : `Показать журнал установки (${lines.length})`}
      </button>

      {open ? (
        <pre className={styles.log}>
          {lines.join('\n')}
        </pre>
      ) : null}
    </div>
  );
}
