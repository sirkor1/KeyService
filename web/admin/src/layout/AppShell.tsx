import { Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { dashboard } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import styles from './AppShell.module.css';

/**
 * Каркас панели: липкая шапка, меню слева, содержимое справа.
 *
 * Сводка запрашивается один раз здесь и раздаётся шапке и меню —
 * иначе каждый экран дёргал бы её заново.
 */
export function AppShell() {
  const { data: summary } = useQuery({
    queryKey: qk.dashboard,
    queryFn: dashboard.summary,
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });

  return (
    <div className={styles.shell}>
      <Header summary={summary} />
      <div className={styles.body}>
        <Sidebar summary={summary} />
        <main className={styles.main}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
