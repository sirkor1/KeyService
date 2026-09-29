import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { keys as keysApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { KeyListItem } from '@/api/types';
import { Btn, BtnLink } from '@/components/Btn';
import { ConfirmDialog, Dialog } from '@/components/Dialog';
import { useToast } from '@/components/Toast';
import { useAuth } from '@/auth/AuthProvider';
import { FilterBar, SearchInput, Seg } from '@/components/Filters';
import { ErrorBanner, Stacked } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { Table, type Column } from '@/components/Table';
import { formatBytes, formatDate, joinMeta } from '@/lib/format';
import { keyStatus } from '@/lib/labels';
import { hasTrafficStats, NO_TRAFFIC_STATS_HINT } from '@/lib/protocols';

const STATUS_TABS = [
  { value: '', label: 'Все' },
  { value: 'active', label: 'активен' },
  { value: 'revoked', label: 'отозван' },
  { value: 'expired', label: 'истёк' },
];

function buildColumns(
  canWrite: boolean,
  onRevoke: (key: KeyListItem) => void,
  onShowUri: (key: KeyListItem) => void,
): Column<KeyListItem>[] {
  const base = baseColumns;
  if (!canWrite) return base;

  return [
    ...base,
    {
      key: 'actions',
      header: 'Действия',
      width: '13%',
      align: 'right',
      noEllipsis: true,
      render: (row) =>
        // Отозванный ключ отзывать нечего, скачивать тоже: конфиг стёрт.
        row.status === 'revoked' ? (
          <span>—</span>
        ) : (
          <>
            {row.source === 'router' ? (row.routerId ? <Link className="btn btn-ghost" to={`/routers/${row.routerId}`}>Профиль роутера</Link> : null) : <>
            <a className="btn btn-ghost" href={keysApi.downloadUrl(row.id)} download>
              Скачать
            </a>
            <Btn variant="ghost" onClick={() => onShowUri(row)}>
              URI
            </Btn>
            </>}
            <Btn variant="ghost" onClick={() => onRevoke(row)}>
              Отозвать
            </Btn>
          </>
        ),
    },
  ];
}

const baseColumns: Column<KeyListItem>[] = [
  {
    key: 'shortId',
    header: 'Ключ',
    width: '13%',
    render: (row) => <span className="mono">{row.shortId}</span>,
    title: (row) => row.shortId,
  },
  {
    key: 'owner',
    header: 'Владелец',
    width: '19%',
    noEllipsis: true,
    render: (row) => <><Stacked primary={row.ownerName ?? '—'} secondary={row.deviceName} />{row.routerId ? <Link to={`/routers/${row.routerId}`}>Наблюдение за роутером</Link> : row.source === 'router' ? <span>Ключ роутера</span> : null}</>,
    title: (row) => joinMeta(row.ownerName, row.deviceName),
  },
  {
    key: 'server',
    header: 'Сервер · протокол',
    width: '20%',
    noEllipsis: true,
    render: (row) => (
      <Stacked primary={row.serverName ?? '—'} secondary={row.protocolDisplayName} />
    ),
    title: (row) => joinMeta(row.serverName, row.protocolDisplayName),
  },
  { key: 'issued', header: 'Выдан', width: '11%', render: (row) => formatDate(row.issuedAt) },
  {
    key: 'expires',
    header: 'Действует до',
    width: '12%',
    render: (row) => formatDate(row.expiresAt),
  },
  {
    key: 'traffic',
    header: 'Трафик',
    width: '10%',
    render: (row) => (
      <span className="tabular">
        {hasTrafficStats(row.protocolKind) ? formatBytes(row.trafficBytes) : '—'}
      </span>
    ),
    title: (row) => (hasTrafficStats(row.protocolKind) ? undefined : NO_TRAFFIC_STATS_HINT),
  },
  {
    key: 'status',
    header: 'Статус',
    width: '12%',
    noEllipsis: true,
    render: (row) => <StatusTag status={keyStatus[row.status]} />,
  },
];

export function KeysPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { show } = useToast();
  const { can } = useAuth();

  const [pendingRevoke, setPendingRevoke] = useState<KeyListItem | null>(null);
  const [uriKey, setUriKey] = useState<KeyListItem | null>(null);
  const [vpnUri, setVpnUri] = useState<string | null>(null);
  const [uriError, setUriError] = useState<string | null>(null);
  const [uriLoading, setUriLoading] = useState(false);

  const search = params.get('search') ?? '';
  const status = params.get('status') ?? '';
  const serverId = params.get('serverId') ?? '';
  const userId = params.get('userId') ?? '';

  const query = useQuery({
    queryKey: qk.keyList({ search, status, serverId, userId }),
    queryFn: () => keysApi.list({ search, status, serverId, userId }),
    placeholderData: keepPreviousData,
  });

  const revoke = useMutation({
    mutationFn: (id: string) => keysApi.revoke(id),
    onSuccess: (result) => {
      setPendingRevoke(null);

      // pendingRevoke означает, что узел был недоступен и peer на нём остался.
      // Молчать об этом нельзя: оператор решит, что доступ закрыт.
      show(
        result.status === 'pendingRevoke'
          ? `Ключ ${result.shortId}: узел недоступен, доступ пока сохраняется`
          : `Ключ ${result.shortId} отозван`,
      );

      void queryClient.invalidateQueries({ queryKey: qk.keys });
      void queryClient.invalidateQueries({ queryKey: qk.dashboard });
    },
    onError: () => {
      setPendingRevoke(null);
      show('Не удалось отозвать ключ');
    },
  });

  async function loadUri(keyId: string) {
    setUriLoading(true);
    setUriError(null);
    setVpnUri(null);

    try {
      const secret = await keysApi.secret(keyId);
      setVpnUri(secret.vpnUri);
    } catch (error) {
      setUriError(
        error instanceof ApiError
          ? error.message
          : 'Не удалось получить URI ключа.',
      );
    } finally {
      setUriLoading(false);
    }
  }

  function openUri(key: KeyListItem) {
    setUriKey(key);
    void loadUri(key.id);
  }

  function closeUri() {
    setUriKey(null);
    setVpnUri(null);
    setUriError(null);
  }

  async function copyUri() {
    if (!vpnUri) return;

    try {
      await navigator.clipboard.writeText(vpnUri);
      show('Ссылка скопирована');
    } catch {
      show('Не удалось скопировать ссылку');
    }
  }

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  return (
    <>
      <PageHeader
        kicker="Клиенты"
        title="Выданные ключи"
        actions={
          <BtnLink to="/keys/issue" variant="primary">
            Выдать ключ
          </BtnLink>
        }
      />

      <FilterBar shown={query.data?.items.length ?? 0} total={query.data?.total ?? 0}>
        <SearchInput
          value={search}
          onChange={(value) => setParam('search', value)}
          placeholder="Поиск по владельцу или ключу"
        />
        <Seg
          name="Статус"
          value={status}
          options={STATUS_TABS}
          onChange={(value) => setParam('status', value)}
        />
      </FilterBar>

      {query.isPending ? <Spinner /> : query.isError ? (
        <ErrorBanner message="Не удалось загрузить список ключей." onRetry={() => void query.refetch()} />
      ) : (
        <Table
          columns={buildColumns(can('panel:write'), setPendingRevoke, openUri)}
          rows={query.data?.items ?? []}
          rowKey={(row) => row.id}
          empty="Ключей пока нет."
        />
      )}

      {pendingRevoke ? (
        <ConfirmDialog
          title={`Отозвать ключ ${pendingRevoke.shortId}?`}
          body="Устройство потеряет доступ в течение минуты. Отозванный ключ нельзя восстановить — потребуется выдать новый."
          confirmLabel="Отозвать"
          busy={revoke.isPending}
          onConfirm={() => revoke.mutate(pendingRevoke.id)}
          onCancel={() => setPendingRevoke(null)}
        />
      ) : null}

      {uriKey ? (
        <Dialog
          title={`URI ключа ${uriKey.shortId}`}
          onClose={closeUri}
          actions={
            <>
              {vpnUri ? (
                <Btn variant="primary" onClick={() => void copyUri()}>
                  Скопировать URI
                </Btn>
              ) : null}
              <Btn variant="secondary" onClick={closeUri}>
                Закрыть
              </Btn>
            </>
          }
        >
          {uriLoading ? <Spinner /> : uriError ? (
            <ErrorBanner message={uriError} onRetry={() => void loadUri(uriKey.id)} />
          ) : vpnUri ? (
            <div className="field">
              <label htmlFor="key-vpn-uri">Ссылка для импорта</label>
              <textarea id="key-vpn-uri" className="input" readOnly rows={5} value={vpnUri} />
            </div>
          ) : null}
        </Dialog>
      ) : null}
    </>
  );
}
