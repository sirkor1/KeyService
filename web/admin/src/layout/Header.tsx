import { useNavigate } from 'react-router-dom';
import type { DashboardSummary } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { initials } from '@/lib/format';
import { userRole } from '@/lib/labels';
import styles from './Header.module.css';

export function Header({ summary }: { summary: DashboardSummary | undefined }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const displayName = user?.displayName ?? user?.username ?? '—';

  return (
    <header className={styles.header}>
      <div className={styles.brand}>
        <span className={styles.brandName}>AMNEZIA</span>
        <span className={styles.brandKicker}>Панель управления</span>
      </div>

      <div className={styles.stats}>
        <span>
          Узлов в работе — {summary?.serversOk ?? '—'}/{summary?.serversTotal ?? '—'}
        </span>
        <span className={styles.statsDivider} aria-hidden="true" />
        <span>Активных ключей — {summary?.keysActive ?? '—'}</span>
      </div>

      <Btn variant="secondary" onClick={() => navigate('/logs')}>
        Журнал
      </Btn>

      <div className={styles.user}>
        <span className={styles.avatar} aria-hidden="true">
          {initials(displayName)}
        </span>
        <span className={styles.userInfo}>
          <span className={styles.userName}>{displayName}</span>
          <span className={styles.userRole}>{user ? userRole[user.role] : ''}</span>
        </span>
        <Btn
          variant="ghost"
          onClick={() => {
            void logout().then(() => navigate('/login', { replace: true }));
          }}
        >
          Выйти
        </Btn>
      </div>
    </header>
  );
}
