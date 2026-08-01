import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/auth/AuthProvider';
import { ApiError } from '@/api/client';
import { servers } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { KeyListItem, ProtocolDetail } from '@/api/types';
import { Btn, BtnLink, cx } from '@/components/Btn';
import { ConfirmDialog } from '@/components/Dialog';
import { KpiRow } from '@/components/KpiRow';
import { DefRow, ErrorBanner, MaskedValue, SectionTitle, Stacked } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag, Tag } from '@/components/Tag';
import { Table, type Column } from '@/components/Table';
import { formatBytes, formatDate, formatPercent, joinMeta } from '@/lib/format';
import { keyStatus, protocolState, serverStatus, sshAuthType } from '@/lib/labels';
import { hasTrafficStats, NO_TRAFFIC_STATS_HINT } from '@/lib/protocols';
import styles from './ServerDetailPage.module.css';

const keyColumns: Column<KeyListItem>[] = [
  {
    key: 'shortId',
    header: 'Ключ',
    width: '18%',
    render: (row) => <span className="mono">{row.shortId}</span>,
    title: (row) => row.shortId,
  },
  {
    key: 'owner',
    header: 'Владелец',
    width: '22%',
    noEllipsis: true,
    render: (row) => <Stacked primary={row.ownerName ?? '—'} secondary={row.deviceName} />,
    title: (row) => joinMeta(row.ownerName, row.deviceName),
  },
  {
    key: 'protocol',
    header: 'Протокол',
    width: '18%',
    render: (row) => row.protocolDisplayName ?? '—',
  },
  { key: 'issued', header: 'Выдан', width: '13%', render: (row) => formatDate(row.issuedAt) },
  {
    key: 'expires',
    header: 'Действует до',
    width: '14%',
    render: (row) => formatDate(row.expiresAt),
  },
  {
    key: 'traffic',
    header: 'Трафик',
    width: '9%',
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
    width: '10%',
    noEllipsis: true,
    render: (row) => <StatusTag status={keyStatus[row.status]} />,
  },
];

function ProtocolCard({ protocol }: { protocol: ProtocolDetail }) {
  const meta = protocol.xray
    ? joinMeta(
        `порт ${protocol.port}/${protocol.transportProto}`,
        `SNI ${protocol.xray.siteName}`,
        'x25519',
      )
    : joinMeta(
        `порт ${protocol.port}/${protocol.transportProto}`,
        protocol.mtu ? `MTU ${protocol.mtu}` : null,
        protocol.wg?.obfuscation
          ? `Jc ${protocol.wg.obfuscation.jc}, Jmin ${protocol.wg.obfuscation.jmin}, Jmax ${protocol.wg.obfuscation.jmax}`
          : null,
      );

  return (
    <article className={styles.protocol}>
      <div className={styles.protocolHead}>
        <span className={styles.protocolName}>{protocol.displayName}</span>
        <StatusTag status={protocolState[protocol.state]} />
        {!protocol.isCached && <Tag tone="outline">параметры не вычитаны</Tag>}
      </div>

      <div className={styles.protocolMeta}>{meta}</div>

      <div className={cx(styles.protocolContainer, 'mono')}>
        {joinMeta(protocol.containerName, protocol.containerVersion)}
      </div>

      {protocol.wg && (
        <div className={styles.protocolMeta}>
          {joinMeta(
            `интерфейс ${protocol.wg.interfaceName}`,
            `подсеть ${protocol.wg.subnetAddress}/${protocol.wg.subnetCidr}`,
            protocol.wg.lastKnownPeerIp ? `последний peer ${protocol.wg.lastKnownPeerIp}` : null,
          )}
        </div>
      )}
    </article>
  );
}

export function ServerDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [confirmDelete, setConfirmDelete] = useState(false);

  const server = useQuery({
    queryKey: qk.serverDetail(id),
    queryFn: () => servers.detail(id),
    enabled: Boolean(id),
  });

  const keys = useQuery({
    queryKey: qk.serverKeys(id),
    queryFn: () => servers.keys(id, { pageSize: 5 }),
    enabled: Boolean(id),
  });

  const deleteServer = useMutation({
    mutationFn: () => servers.delete(id),
    onSuccess: () => {
      queryClient.removeQueries({ queryKey: qk.serverDetail(id) });
      void queryClient.invalidateQueries({ queryKey: qk.servers });
      void queryClient.invalidateQueries({ queryKey: qk.dashboard });
      navigate('/servers', { replace: true });
    },
  });

  if (server.isPending) return <Spinner />;
  if (server.isError || !server.data) {
    return <ErrorBanner message="Сервер не найден или недоступен." onRetry={() => void server.refetch()} />;
  }

  const s = server.data;
  const canDeleteFailedInstall = s.status === 'error' && s.kpi.keysActive === 0 && can('panel:write');
  const deleteError = deleteServer.error instanceof ApiError
    ? deleteServer.error.message
    : 'Не удалось удалить запись незавершённой установки.';

  return (
    <>
      <PageHeader
        kicker={joinMeta(s.geo, s.provider) || 'Узел'}
        title={s.name}
        back={{ to: '/servers', label: 'Все серверы' }}
        badge={<StatusTag status={serverStatus[s.status]} />}
        actions={<>
          <BtnLink to="/keys/issue" variant="secondary">
            Выдать ключ
          </BtnLink>
          {canDeleteFailedInstall ? (
            <Btn variant="ghost" onClick={() => setConfirmDelete(true)}>
              Удалить запись установки
            </Btn>
          ) : null}
        </>}
      />

      <KpiRow
        compact
        cells={[
          { label: 'Аптайм 30 дней', value: formatPercent(s.kpi.uptime30dPercent) },
          { label: 'Активных ключей', value: String(s.kpi.keysActive) },
          { label: 'Трафик за месяц', value: formatBytes(s.kpi.trafficBytes) },
        ]}
      />

      <div className={styles.columns}>
        <section>
          <SectionTitle>Параметры узла</SectionTitle>

          <DefRow label="Имя сервера">{s.name}</DefRow>
          <DefRow label="IP-адрес">
            <span className="mono tabular">{s.host}</span>
          </DefRow>
          <DefRow label="SSH-порт">
            <span className="tabular">{s.ssh.port}</span>
          </DefRow>
          <DefRow label="Пользователь">{s.ssh.user}</DefRow>
          <DefRow label="Тип доступа">{sshAuthType[s.ssh.authType] ?? s.ssh.authType}</DefRow>
          <DefRow label="Отпечаток хоста">
            <span className="mono">{s.ssh.hostFingerprint ?? 'не зафиксирован'}</span>
          </DefRow>
          <DefRow label={s.ssh.hasPrivateKey ? 'Приватный SSH-ключ' : 'SSH-пароль'}>
            {s.ssh.hasPrivateKey || s.ssh.hasPassword ? (
              <MaskedValue hint={s.ssh.keyType ?? undefined} />
            ) : (
              'не задан'
            )}
          </DefRow>
          <DefRow label="DNS">{joinMeta(s.dns1, s.dns2)}</DefRow>

          {/* Строка появляется только после первой сверки: до неё ноль
              означал бы «расхождений нет», хотя проверки просто не было. */}
          {s.reconciledAt ? (
            <DefRow label="Сверка peer-ов">
              {joinMeta(
                s.orphanPeerCount > 0
                  ? `${s.orphanPeerCount} без выданного ключа`
                  : 'расхождений нет',
                formatDate(s.reconciledAt),
              )}
            </DefRow>
          ) : null}

          <p className={styles.footnote}>
            Секреты не отображаются в интерфейсе и не выгружаются. Значение можно только заменить.
          </p>
        </section>

        <section>
          <SectionTitle>Протоколы и контейнеры</SectionTitle>

          <div className={styles.protocols}>
            {s.protocols.map((protocol) => (
              <ProtocolCard key={protocol.id} protocol={protocol} />
            ))}
          </div>
        </section>
      </div>

      <section className={styles.keysSection}>
        <SectionTitle
          action={
            <BtnLink to={`/keys?serverId=${s.id}`} variant="ghost">
              Все ключи →
            </BtnLink>
          }
        >
          Ключи этого сервера
        </SectionTitle>

        {keys.isPending ? (
          <Spinner />
        ) : keys.isError ? (
          <ErrorBanner message="Не удалось загрузить ключи этого сервера." onRetry={() => void keys.refetch()} />
        ) : (
          <Table
            columns={keyColumns}
            rows={keys.data?.items ?? []}
            rowKey={(row) => row.id}
            rowHref={(row) => `/keys?search=${row.shortId}`}
            empty="На этом сервере ещё не выдано ни одного ключа."
          />
        )}
      </section>

      {confirmDelete ? (
        <ConfirmDialog
          title={`Удалить запись «${s.name}»?`}
          body={<>
            <p>
              Будет удалена только незавершённая запись узла из панели. Контейнеры,
              файлы и настройки на сервере не удаляются.
            </p>
            {deleteServer.isError ? <ErrorBanner message={deleteError} /> : null}
          </>}
          confirmLabel="Удалить запись"
          busy={deleteServer.isPending}
          onConfirm={() => deleteServer.mutate()}
          onCancel={() => {
            deleteServer.reset();
            setConfirmDelete(false);
          }}
        />
      ) : null}
    </>
  );
}
