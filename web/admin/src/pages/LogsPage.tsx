import { useSearchParams } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { logs as logsApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import { FilterBar, Seg } from '@/components/Filters';
import { EmptyState, ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { formatLogTime } from '@/lib/format';
import { auditLevel } from '@/lib/labels';
import styles from './LogsPage.module.css';

const LEVEL_TABS = [
  { value: '', label: 'Все' },
  { value: 'info', label: 'info' },
  { value: 'warn', label: 'внимание' },
  { value: 'error', label: 'ошибка' },
];

export function LogsPage() {
  const [params, setParams] = useSearchParams();
  const level = params.get('level') ?? '';

  const query = useQuery({
    queryKey: qk.logList({ level }),
    queryFn: () => logsApi.list({ level, pageSize: 100 }),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <PageHeader kicker="Система" title="Журнал событий" />

      <FilterBar shown={query.data?.items.length ?? 0} total={query.data?.total ?? 0}>
        <Seg
          name="Уровень"
          value={level}
          options={LEVEL_TABS}
          onChange={(value) => {
            const next = new URLSearchParams(params);
            if (value) next.set('level', value);
            else next.delete('level');
            setParams(next, { replace: true });
          }}
        />
      </FilterBar>

      {query.isPending ? (
        <Spinner />
      ) : query.isError ? (
        <ErrorBanner message="Не удалось загрузить журнал." onRetry={() => void query.refetch()} />
      ) : query.data && query.data.items.length > 0 ? (
        /* Не таблица, а сетка: строки журнала разной длины, и колонка
           события должна тянуться, а не ломать выравнивание соседей. */
        <div className={styles.list}>
          {query.data.items.map((entry) => (
            <div key={entry.id} className={styles.row}>
              <span className={styles.time}>{formatLogTime(entry.at)}</span>
              <span className={styles.level}>
                <StatusTag status={auditLevel[entry.level]} />
              </span>
              <span className={styles.event}>{entry.message}</span>
              <span className={styles.target}>
                {entry.targetName ?? entry.targetType ?? 'система'}
                {entry.actorName ? ` · ${entry.actorName}` : ''}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState
          title="Записей пока нет"
          hint="Здесь появятся действия администраторов: добавление узлов, выдача и отзыв ключей, входы в панель."
        />
      )}
    </>
  );
}
