import { useSearchParams } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { dashboard, servers } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { ServerListItem } from '@/api/types';
import { BtnLink } from '@/components/Btn';
import { FilterBar, SearchInput, Seg } from '@/components/Filters';
import { KpiRow } from '@/components/KpiRow';
import { LoadBar, ErrorBanner, Stacked } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { Table, type Column } from '@/components/Table';
import { formatBytes, formatNumber, joinMeta } from '@/lib/format';
import { serverStatus, sshAuthType } from '@/lib/labels';

const PROTOCOL_TABS = [
  { value: '', label: 'Все' },
  { value: 'awg2', label: 'AmneziaWG' },
  { value: 'wireguard', label: 'WireGuard' },
  { value: 'xray', label: 'VLESS Reality' },
];

const columns: Column<ServerListItem>[] = [
  {
    key: 'name',
    header: 'Сервер',
    width: '26%',
    noEllipsis: true,
    render: (row) => <Stacked primary={row.name} secondary={joinMeta(row.geo, row.provider)} />,
    title: (row) => joinMeta(row.name, row.geo, row.provider),
  },
  {
    key: 'host',
    header: 'IP · SSH',
    width: '18%',
    noEllipsis: true,
    render: (row) => (
      <Stacked
        primary={<span className="mono tabular">{row.host}</span>}
        secondary={joinMeta(`порт ${row.sshPort}`, sshAuthType[row.sshAuthType])}
      />
    ),
    title: (row) => row.host,
  },
  {
    key: 'protocols',
    header: 'Протоколы',
    width: '18%',
    render: (row) => row.protocols.map((p) => p.displayName).join(' · ') || '—',
    title: (row) => row.protocols.map((p) => `${p.displayName} (порт ${p.port})`).join(' · '),
  },
  {
    key: 'keys',
    header: 'Ключи',
    width: '8%',
    render: (row) => <span className="tabular">{formatNumber(row.keysCount)}</span>,
  },
  {
    key: 'load',
    header: 'Загрузка',
    width: '13%',
    noEllipsis: true,
    render: (row) => <LoadBar percent={row.loadPercent} />,
  },
  {
    key: 'traffic',
    header: 'Трафик',
    width: '9%',
    render: (row) => <span className="tabular">{formatBytes(row.trafficBytes)}</span>,
  },
  {
    key: 'status',
    header: 'Статус',
    width: '8%',
    noEllipsis: true,
    render: (row) => <StatusTag status={serverStatus[row.status]} />,
  },
];

export function ServersPage() {
  const [params, setParams] = useSearchParams();

  const search = params.get('search') ?? '';
  const protocol = params.get('protocol') ?? '';

  const query = useQuery({
    queryKey: qk.serverList({ search, protocol }),
    queryFn: () => servers.list({ search, protocol }),
    placeholderData: keepPreviousData,
  });

  const summary = useQuery({ queryKey: qk.dashboard, queryFn: dashboard.summary });

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  return (
    <>
      <PageHeader
        kicker="Инфраструктура"
        title="Активные серверы"
        actions={
          <BtnLink to="/servers/add" variant="primary">
            Добавить сервер
          </BtnLink>
        }
      />

      <KpiRow
        cells={[
          {
            label: 'Узлы онлайн',
            value: `${summary.data?.serversOk ?? '—'} / ${summary.data?.serversTotal ?? '—'}`,
          },
          { label: 'Выданных ключей', value: formatNumber(summary.data?.keysActive) },
          { label: 'Трафик за месяц', value: formatBytes(summary.data?.trafficMonthBytes) },
          {
            label: 'Требуют внимания',
            value: formatNumber(summary.data?.attention.total ?? 0),
            accent: (summary.data?.attention.total ?? 0) > 0,
          },
        ]}
      />

      <FilterBar shown={query.data?.items.length ?? 0} total={query.data?.total ?? 0}>
        <SearchInput
          value={search}
          onChange={(value) => setParam('search', value)}
          placeholder="Поиск по имени или IP"
        />
        <Seg
          name="Протокол"
          value={protocol}
          options={PROTOCOL_TABS}
          onChange={(value) => setParam('protocol', value)}
        />
      </FilterBar>

      {query.isPending ? <Spinner /> : query.isError ? (
        <ErrorBanner message="Не удалось загрузить список серверов." onRetry={() => void query.refetch()} />
      ) : (
        <Table
          columns={columns}
          rows={query.data?.items ?? []}
          rowKey={(row) => row.id}
          rowHref={(row) => `/servers/${row.id}`}
          empty="Серверов пока нет."
        />
      )}
    </>
  );
}
