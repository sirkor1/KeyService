import { useMemo, useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { events as eventsApi, keys as keysApi, servers as serversApi, settings as settingsApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { IssuedKey, ServerListItem } from '@/api/types';
import { Btn } from '@/components/Btn';
import { Seg } from '@/components/Filters';
import { ErrorBanner, MaskedValue, SectionTitle } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { useToast } from '@/components/Toast';
import { BYTES_IN_GB, joinMeta } from '@/lib/format';
import styles from './IssueKeyPage.module.css';

const ISSUE_POLL_MS = 1000;

function sleep(ms: number) {
  return new Promise<void>((resolve) => window.setTimeout(resolve, ms));
}

export function IssueKeyPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { show } = useToast();

  const serversQuery = useQuery({
    queryKey: qk.serverList({}),
    queryFn: () => serversApi.list({ pageSize: 100 }),
  });

  const settingsQuery = useQuery({ queryKey: qk.settings, queryFn: settingsApi.get });

  const [ownerName, setOwnerName] = useState('');
  const [contact, setContact] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [label, setLabel] = useState('');
  const [serverId, setServerId] = useState(params.get('serverId') ?? '');
  const [protocolId, setProtocolId] = useState('');
  const [expiryDays, setExpiryDays] = useState('');
  const [trafficLimitGb, setTrafficLimitGb] = useState('');
  const [issued, setIssued] = useState<IssuedKey | null>(null);

  // Выдавать можно только с работающих узлов: на недоступном заведение
  // peer-а всё равно упадёт на SSH.
  const available = useMemo(
    () => (serversQuery.data?.items ?? []).filter((s) => s.status === 'ok'),
    [serversQuery.data],
  );

  const selectedServer = available.find((s) => s.id === serverId);
  const protocolOptions = (selectedServer?.protocols ?? []).map((p) => ({
    value: p.id,
    label: p.displayName,
  }));

  const effectiveProtocolId = protocolId || protocolOptions[0]?.value || '';

  // Подсказка в поле квоты повторяет значение из настроек панели — то самое,
  // которое подставит бэкенд, если поле оставить пустым.
  const defaultTrafficBytes = settingsQuery.data?.defaultTrafficLimitBytes ?? null;
  const defaultTrafficGb =
    defaultTrafficBytes === null ? 'без ограничения' : String(defaultTrafficBytes / BYTES_IN_GB);

  const issue = useMutation({
    mutationFn: async () => {
      const accepted = await keysApi.issue({
        serverId,
        ...(effectiveProtocolId ? { protocolId: effectiveProtocolId } : {}),
        ownerName: ownerName.trim(),
        ...(contact.trim() ? { contact: contact.trim() } : {}),
        ...(deviceName.trim() ? { deviceName: deviceName.trim() } : {}),
        ...(label.trim() ? { label: label.trim() } : {}),
        ...(expiryDays === '' ? {} : { expiryDays: Number(expiryDays) }),
        // Как и срок: пусто — из настроек панели, 0 — без ограничения.
        // Ноль бэкенд превращает в отсутствие квоты сам.
        ...(trafficLimitGb === ''
          ? {}
          : { trafficLimitBytes: Number(trafficLimitGb) * BYTES_IN_GB }),
      });
      const event = await waitForIssue(accepted.eventId);

      if (event.status !== 'succeeded') {
        throw new ApiError(400, event.error ?? 'Не удалось выдать ключ.');
      }

      const [detail, secret] = await Promise.all([
        keysApi.detail(accepted.keyId),
        keysApi.secret(accepted.keyId),
      ]);

      return { key: detail.summary, ...secret };
    },
    onSuccess: (result) => {
      setIssued(result);
      show(`Ключ ${result.key.shortId} выдан`);
      void queryClient.invalidateQueries({ queryKey: qk.keys });
      void queryClient.invalidateQueries({ queryKey: qk.dashboard });
    },
  });

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    issue.mutate();
  }

  function downloadConf() {
    if (!issued) return;

    // Файл собираем локально из уже полученного ответа: повторно запрашивать
    // конфиг у сервера незачем, а секрет и так у нас в памяти.
    const blob = new Blob([issued.fileContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = issued.fileName;
    link.click();

    URL.revokeObjectURL(url);
    show('Файл конфигурации скачан — секрет больше не будет показан');
  }

  const header = (
    <PageHeader
      kicker="Клиенты"
      title="Выдача нового ключа"
      back={{ to: '/keys', label: 'Все ключи' }}
    />
  );

  if (serversQuery.isPending || settingsQuery.isPending) {
    return <>{header}<Spinner label="Загружаем параметры выдачи…" /></>;
  }

  if (serversQuery.isError) {
    return <>{header}<ErrorBanner message="Не удалось загрузить список серверов." onRetry={() => void serversQuery.refetch()} /></>;
  }

  if (settingsQuery.isError) {
    return <>{header}<ErrorBanner message="Не удалось загрузить настройки по умолчанию." onRetry={() => void settingsQuery.refetch()} /></>;
  }

  return (
    <>
      {header}

      {available.length === 0 ? (
        <ErrorBanner message="Нет ни одного работающего узла. Выдать ключ не с чего." />
      ) : null}

      {issue.isError ? (
        <ErrorBanner
          message={
            issue.error instanceof ApiError
              ? issue.error.message
              : 'Не удалось выдать ключ.'
          }
        />
      ) : null}

      <div className={styles.columns}>
        <form className={styles.form} onSubmit={handleSubmit} aria-busy={issue.isPending}>
          <div className="field">
            <label htmlFor="owner">Владелец</label>
            <input
              id="owner"
              className="input"
              placeholder="Имя или e-mail клиента"
              value={ownerName}
              disabled={issue.isPending}
              onChange={(e) => setOwnerName(e.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="contact">Контакт</label>
            <input
              id="contact"
              className="input"
              placeholder="Необязательно: e-mail или @telegram"
              value={contact}
              disabled={issue.isPending}
              onChange={(e) => setContact(e.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="device">Устройство</label>
            <input
              id="device"
              className="input"
              placeholder="iPhone 15, ноутбук…"
              value={deviceName}
              disabled={issue.isPending}
              onChange={(e) => setDeviceName(e.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="label">Метка</label>
            <input
              id="label"
              className="input"
              placeholder="Необязательно"
              value={label}
              disabled={issue.isPending}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="server-list">Сервер</label>
            <div className={styles.serverList} id="server-list">
              {available.map((server) => (
                <ServerOption
                  key={server.id}
                  server={server}
                  checked={server.id === serverId}
                  disabled={issue.isPending}
                  onSelect={() => {
                    setServerId(server.id);
                    // Протокол сбрасываем: у другого узла набор свой.
                    setProtocolId('');
                  }}
                />
              ))}
            </div>
          </div>

          {protocolOptions.length > 0 ? (
            <div className="field">
              <label htmlFor="protocol">Протокол</label>
              <Seg
                name="Протокол"
                value={effectiveProtocolId}
                options={protocolOptions}
                onChange={setProtocolId}
                disabled={issue.isPending}
              />
            </div>
          ) : null}

          <div className="field">
            <label htmlFor="expiry">Срок действия, дней</label>
            <input
              id="expiry"
              className={styles.narrow}
              type="number"
              min={0}
              placeholder={String(settingsQuery.data?.defaultExpiryDays ?? 90)}
              value={expiryDays}
              disabled={issue.isPending}
              onChange={(e) => setExpiryDays(e.target.value)}
            />
            <p className={styles.hint}>Пусто — как в настройках панели, 0 — бессрочно.</p>
          </div>

          <div className="field">
            <label htmlFor="traffic-limit">Лимит трафика, ГБ</label>
            <input
              id="traffic-limit"
              className={styles.narrow}
              type="number"
              min={0}
              placeholder={defaultTrafficGb}
              value={trafficLimitGb}
              disabled={issue.isPending}
              onChange={(e) => setTrafficLimitGb(e.target.value)}
            />
            <p className={styles.hint}>
              Пусто — как в настройках панели, 0 — без ограничения. По исчерпании ключ
              отзывается автоматически.
            </p>
          </div>

          <div className={styles.actions}>
            <Btn
              variant="primary"
              type="submit"
              disabled={issue.isPending || !serverId || !ownerName.trim()}
            >
              {issue.isPending ? 'Создаём ключ…' : 'Создать ключ'}
            </Btn>
            <Btn variant="secondary" onClick={() => navigate('/keys')} disabled={issue.isPending}>
              Отменить
            </Btn>
          </div>
        </form>

        <aside className={styles.preview}>
          <SectionTitle>Предпросмотр ключа</SectionTitle>

          <div className={styles.previewCard}>
            <div className={styles.previewHead}>
              <span className="mono">{issued?.key.shortId ?? 'KEY-НОВЫЙ'}</span>
              <span className={issued ? 'tag tag-neutral' : 'tag tag-outline'}>
                {issued ? 'выдан' : 'черновик'}
              </span>
            </div>

            <PreviewRow label="Сервер">
              {selectedServer ? joinMeta(selectedServer.name, selectedServer.geo) : '—'}
            </PreviewRow>
            <PreviewRow label="Протокол">
              {protocolOptions.find((p) => p.value === effectiveProtocolId)?.label ?? '—'}
            </PreviewRow>
            <PreviewRow label="Endpoint">
              <span className="mono">
                {selectedServer
                  ? `${selectedServer.host}:${
                      selectedServer.protocols.find((p) => p.id === effectiveProtocolId)?.port ?? '—'
                    }`
                  : '—'}
              </span>
            </PreviewRow>
            <PreviewRow label="Туннельный IP">
              <span className="mono">{issued?.key.assignedIp ?? '—'}</span>
            </PreviewRow>
            <PreviewRow label="Приватный ключ">
              <MaskedValue />
            </PreviewRow>

            {issued ? (
              <>
                <div className="field">
                  <label htmlFor="vpn-uri">Ссылка для импорта</label>
                  <textarea id="vpn-uri" className="input" readOnly rows={4} value={issued.vpnUri} />
                </div>

                <div className={styles.previewActions}>
                  <Btn
                    variant="secondary"
                    onClick={() => {
                      void navigator.clipboard.writeText(issued.vpnUri);
                      show('Ссылка скопирована');
                    }}
                  >
                    Скопировать ссылку
                  </Btn>
                  <Btn variant="primary" onClick={downloadConf}>
                    Скачать .conf
                  </Btn>
                </div>
              </>
            ) : null}

            <p className={styles.note}>
              Ключ существует только в скачанном файле и в ссылке выше. Панель хранит отпечаток и не
              сможет показать секрет повторно.
            </p>
          </div>
        </aside>
      </div>
    </>
  );
}

async function waitForIssue(eventId: string) {
  while (true) {
    const event = await eventsApi.get(eventId);
    if (event.status === 'succeeded' || event.status === 'failed' || event.status === 'canceled') {
      return event;
    }

    await sleep(ISSUE_POLL_MS);
  }
}

function PreviewRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className={styles.previewRow}>
      <span className={styles.previewLabel}>{label}</span>
      <span className={styles.previewValue}>{children}</span>
    </div>
  );
}

function ServerOption({
  server,
  checked,
  disabled,
  onSelect,
}: {
  server: ServerListItem;
  checked: boolean;
  disabled: boolean;
  onSelect: () => void;
}) {
  return (
    <label className={checked ? `${styles.serverRow} ${styles.serverRowActive}` : styles.serverRow}>
      <input type="radio" name="server" checked={checked} disabled={disabled} onChange={onSelect} />
      <span className={styles.serverInfo}>
        <span className={styles.serverName}>{server.name}</span>
        <span className={styles.serverMeta}>{joinMeta(server.geo, server.host)}</span>
      </span>
      <span className={styles.serverStats}>
        {server.keysCount} ключей
        {server.loadPercent !== null ? ` · загрузка ${Math.round(server.loadPercent)}%` : ''}
      </span>
    </label>
  );
}
