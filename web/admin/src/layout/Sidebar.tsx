import { NavLink } from 'react-router-dom';
import type { DashboardSummary } from '@/api/types';
import { formatTime } from '@/lib/format';
import { cx } from '@/components/Btn';
import { useAuth } from '@/auth/AuthProvider';
import { useQuery } from '@tanstack/react-query';
import { routerKeys, routersApi } from '@/api/routers';
import styles from './Sidebar.module.css';

interface NavItem {
  to: string;
  label: string;
  badge?: number;
  /** Подсказка к бейджу, если его смысл не очевиден из подписи пункта. */
  badgeTitle?: string;
  /** Скрывать бейдж при нуле: ноль рядом с непустым разделом читается как поломка. */
  hideZeroBadge?: boolean;
  /** Пункт ведёт на экран, который появится в следующей фазе. */
  pending?: boolean;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

function buildGroups(summary: DashboardSummary | undefined, canAdmin: boolean, canWrite: boolean, offlineRouters: number): NavGroup[] {
  const badges = summary?.navBadges;

  return [
    {
      title: 'Инфраструктура',
      items: [
        { to: '/servers', label: 'Серверы', ...(badges ? { badge: badges.servers } : {}) },
        { to: '/servers/add', label: 'Добавить сервер' },
        { to: '/keys', label: 'Ключи', ...(badges ? { badge: badges.keys } : {}) },
      ],
    },
    {
      title: 'Клиенты',
      items: [
        ...(canAdmin ? [{ to: '/users', label: 'Пользователи', ...(badges ? { badge: badges.users } : {}) }] : []),
        ...(canWrite ? [{ to: '/passcodes', label: 'Пригласительные коды' }] : []),
        ...(canAdmin ? [{ to: '/notifications', label: 'Рассылки' }] : []),
        { to: '/keys/issue', label: 'Выдать ключ' },
      ],
    },
    {
      title: 'Наблюдение',
      items: [{ to: '/routers', label: 'Роутеры', badge: offlineRouters, hideZeroBadge: true, badgeTitle: 'Роутеров без связи' }],
    },
    {
      title: 'Система',
      items: [
        {
          to: '/logs',
          label: 'Журнал событий',
          // Здесь не общее число записей, а ошибки за сутки: бейдж должен
          // привлекать внимание, а не показывать размер журнала.
          ...(badges ? { badge: badges.logs } : {}),
          badgeTitle: 'Ошибок за последние сутки',
          hideZeroBadge: true,
        },
        { to: '/settings', label: 'Настройки' },
      ],
    },
  ];
}

export function Sidebar({ summary }: { summary: DashboardSummary | undefined }) {
  const { can } = useAuth();
  const routers = useQuery({ queryKey: routerKeys.list, queryFn: routersApi.list, refetchInterval: 15000 });
  return (
    <nav className={styles.sidebar} aria-label="Основная навигация">
      {buildGroups(summary, can('panel:admin'), can('panel:write'), routers.data?.filter(r => r.state === 'offline').length ?? 0).map((group) => (
        <section key={group.title} className={styles.group}>
          <h6 className={styles.groupTitle}>{group.title}</h6>

          {group.items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/servers'}
              className={({ isActive }) => cx(styles.item, isActive && styles.itemActive)}
            >
              <span className={styles.itemLabel}>{item.label}</span>
              {item.pending ? (
                <span className={styles.itemPending} title="Появится в следующей фазе">
                  скоро
                </span>
              ) : item.badge !== undefined && !(item.hideZeroBadge && item.badge === 0) ? (
                <span className={styles.itemBadge} title={item.badgeTitle}>
                  {item.badge}
                </span>
              ) : null}
            </NavLink>
          ))}
        </section>
      ))}

      <footer className={styles.footer}>
        <div>AmneziaVPN · панель {summary?.appVersion ?? ''}</div>
        <div>
          {summary?.serversTotal ?? 0} узлов · {summary?.keysActive ?? 0} активных ключей
        </div>
        <div>Последняя синхронизация {formatTime(summary?.lastSyncAt)}</div>
      </footer>
    </nav>
  );
}
