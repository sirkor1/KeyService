import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import styles from './PageHeader.module.css';

/**
 * Шапка экрана: акцентный кикер, заголовок, действия справа и линейка снизу.
 * Один и тот же порядок на всех экранах макета.
 */
export function PageHeader({
  kicker,
  title,
  back,
  badge,
  actions,
}: {
  kicker: string;
  title: string;
  back?: { to: string; label: string };
  badge?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header>
      {back && (
        <Link to={back.to} className={styles.back}>
          ← {back.label}
        </Link>
      )}

      <div className={styles.row}>
        <div className={styles.titleBlock}>
          <div className={styles.kicker}>{kicker}</div>
          <div className={styles.titleRow}>
            <h2 className={styles.title}>{title}</h2>
            {badge}
          </div>
        </div>

        {actions && <div className={styles.actions}>{actions}</div>}
      </div>

      <hr className="hr" />
    </header>
  );
}
