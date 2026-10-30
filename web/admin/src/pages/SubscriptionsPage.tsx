import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import {
  settings as settingsApi,
  subscriptions as subscriptionsApi,
  users as usersApi,
} from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { SubscriptionListItem, UserListItem } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ConfirmDialog, Dialog } from '@/components/Dialog';
import { FilterBar, SearchInput, Seg } from '@/components/Filters';
import { ErrorBanner, Stacked } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { Table, type Column } from '@/components/Table';
import { useToast } from '@/components/Toast';
import { BYTES_IN_GB, formatBytes, formatDate, joinMeta } from '@/lib/format';
import { subscriptionSource, subscriptionStatus } from '@/lib/labels';
import styles from './SubscriptionsPage.module.css';

const PAGE_SIZE = 100;

const STATUS_TABS = [
  { value: '', label: 'Все' },
  { value: 'active', label: 'активна' },
  { value: 'revoked', label: 'отозвана' },
];

/** Минимум символов в поиске пользователя: короче — список почти целиком, и выбирать не из чего. */
const USER_SEARCH_MIN = 2;

function trafficCell(row: SubscriptionListItem): string {
  const used = row.trafficBytes > 0 ? formatBytes(row.trafficBytes) : '0 Б';
  return `${used} / ${row.trafficLimitBytes ? formatBytes(row.trafficLimitBytes) : 'без лимита'}`;
}

interface Handlers {
  onLink: (row: SubscriptionListItem) => void;
  onLimits: (row: SubscriptionListItem) => void;
  onRegenerate: (row: SubscriptionListItem) => void;
  onRevoke: (row: SubscriptionListItem) => void;
}

const baseColumns: Column<SubscriptionListItem>[] = [
  {
    key: 'user',
    header: 'Пользователь',
    width: '17%',
    noEllipsis: true,
    render: (row) => <Stacked primary={row.userName ?? 'удалён'} secondary={subscriptionSource[row.source]} />,
    title: (row) => joinMeta(row.userName, subscriptionSource[row.source]),
  },
  {
    key: 'status',
    header: 'Статус',
    width: '17%',
    noEllipsis: true,
    render: (row) => <StatusTag status={subscriptionStatus(row.status, row.revokeReason)} />,
  },
  {
    key: 'expires',
    header: 'Действует до',
    width: '12%',
    render: (row) => (row.expiresAt ? formatDate(row.expiresAt) : 'бессрочно'),
  },
  {
    key: 'traffic',
    header: 'Трафик / лимит',
    width: '17%',
    render: (row) => <span className="tabular">{trafficCell(row)}</span>,
    title: (row) => trafficCell(row),
  },
  { key: 'created', header: 'Создана', width: '11%', render: (row) => formatDate(row.createdAt) },
];

function buildColumns(canWrite: boolean, handlers: Handlers): Column<SubscriptionListItem>[] {
  if (!canWrite) return baseColumns;

  return [
    ...baseColumns,
    {
      key: 'actions',
      header: 'Действия',
      width: '26%',
      align: 'right',
      noEllipsis: true,
      render: (row) =>
        // Отозванная подписка необратима: менять в ней нечего, остаётся строка в истории.
        row.status !== 'active' ? (
          <span>—</span>
        ) : (
          <>
            <Btn variant="ghost" onClick={() => handlers.onLink(row)}>Ссылка</Btn>
            <Btn variant="ghost" onClick={() => handlers.onLimits(row)}>Лимиты</Btn>
            <Btn variant="ghost" onClick={() => handlers.onRegenerate(row)}>Перевыпустить</Btn>
            <Btn variant="ghost" onClick={() => handlers.onRevoke(row)}>Отозвать</Btn>
          </>
        ),
    },
  ];
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

export function SubscriptionsPage() {
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { show } = useToast();
  const { can } = useAuth();

  const [creating, setCreating] = useState(false);
  const [linkFor, setLinkFor] = useState<SubscriptionListItem | null>(null);
  const [limitsFor, setLimitsFor] = useState<SubscriptionListItem | null>(null);
  const [pendingRegenerate, setPendingRegenerate] = useState<SubscriptionListItem | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<SubscriptionListItem | null>(null);

  const search = params.get('search') ?? '';
  const status = params.get('status') ?? '';

  const canWrite = can('panel:write');
  // Список пользователей отдаёт только панельный администратор (GET /api/users), поэтому и выдача
  // подписки из панели доступна ему: оператору выбрать владельца было бы нечем.
  const canCreate = canWrite && can('panel:admin');

  const query = useQuery({
    queryKey: qk.subscriptionList({ search, status, pageSize: PAGE_SIZE }),
    queryFn: () => subscriptionsApi.list({ search, status, pageSize: PAGE_SIZE }),
    placeholderData: keepPreviousData,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: qk.subscriptions });
    void queryClient.invalidateQueries({ queryKey: qk.servers });
  };

  const revoke = useMutation({
    mutationFn: (id: string) => subscriptionsApi.revoke(id),
    onSuccess: () => {
      setPendingRevoke(null);
      show('Подписка отозвана');
      invalidate();
    },
  });

  const regenerate = useMutation({
    mutationFn: (id: string) => subscriptionsApi.regenerate(id),
    onSuccess: () => {
      setPendingRegenerate(null);
      show('Ссылка перевыпущена: прежняя больше не работает');
      invalidate();
    },
  });

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
        title="Подписки"
        actions={
          canCreate ? (
            <Btn variant="primary" onClick={() => setCreating(true)}>
              Создать подписку
            </Btn>
          ) : null
        }
      />

      <FilterBar shown={query.data?.items.length ?? 0} total={query.data?.total ?? 0}>
        <SearchInput
          value={search}
          onChange={(value) => setParam('search', value)}
          placeholder="Поиск по пользователю"
        />
        <Seg name="Статус" value={status} options={STATUS_TABS} onChange={(value) => setParam('status', value)} />
      </FilterBar>

      {revoke.isError ? <ErrorBanner message={errorMessage(revoke.error, 'Не удалось отозвать подписку.')} /> : null}
      {regenerate.isError ? (
        <ErrorBanner message={errorMessage(regenerate.error, 'Не удалось перевыпустить ссылку.')} />
      ) : null}

      {query.isPending ? <Spinner /> : query.isError ? (
        <ErrorBanner message="Не удалось загрузить список подписок." onRetry={() => void query.refetch()} />
      ) : (
        <Table
          columns={buildColumns(canWrite, {
            onLink: setLinkFor,
            onLimits: setLimitsFor,
            onRegenerate: (row) => { regenerate.reset(); setPendingRegenerate(row); },
            onRevoke: (row) => { revoke.reset(); setPendingRevoke(row); },
          })}
          rows={query.data?.items ?? []}
          rowKey={(row) => row.id}
          empty="Подписок пока нет."
        />
      )}

      {creating ? (
        <CreateDialog
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            show('Подписка создана');
            invalidate();
          }}
        />
      ) : null}

      {linkFor ? <LinkDialog subscription={linkFor} onClose={() => setLinkFor(null)} /> : null}

      {limitsFor ? (
        <LimitsDialog
          subscription={limitsFor}
          onClose={() => setLimitsFor(null)}
          onDone={() => {
            setLimitsFor(null);
            show('Срок и лимит обновлены');
            invalidate();
          }}
        />
      ) : null}

      {pendingRegenerate ? (
        <ConfirmDialog
          title={`Перевыпустить ссылку: ${pendingRegenerate.userName ?? 'подписка'}?`}
          body="Старая ссылка и все настроенные по ней устройства перестанут работать. Пользователю придётся заново добавить подписку по новой ссылке."
          confirmLabel="Перевыпустить"
          busy={regenerate.isPending}
          onConfirm={() => regenerate.mutate(pendingRegenerate.id)}
          onCancel={() => setPendingRegenerate(null)}
        />
      ) : null}

      {pendingRevoke ? (
        <ConfirmDialog
          title={`Отозвать подписку: ${pendingRevoke.userName ?? 'подписка'}?`}
          body="Ссылка перестанет отдаваться сразу, а подключения закроются, когда узлы применят изменение. Отозванную подписку нельзя восстановить — потребуется создать новую."
          confirmLabel="Отозвать"
          busy={revoke.isPending}
          onConfirm={() => revoke.mutate(pendingRevoke.id)}
          onCancel={() => setPendingRevoke(null)}
        />
      ) : null}
    </>
  );
}

// ── Создание ─────────────────────────────────────────────────────────────────

function CreateDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [userSearch, setUserSearch] = useState('');
  const [selected, setSelected] = useState<UserListItem | null>(null);
  const [expiryDays, setExpiryDays] = useState('');
  const [trafficLimitGb, setTrafficLimitGb] = useState('');

  const term = userSearch.trim();
  const users = useQuery({
    queryKey: qk.userList({ search: term, pageSize: 20 }),
    queryFn: () => usersApi.list({ search: term, pageSize: 20 }),
    enabled: term.length >= USER_SEARCH_MIN,
    placeholderData: keepPreviousData,
  });
  const settings = useQuery({ queryKey: qk.settings, queryFn: settingsApi.get });

  const create = useMutation({
    mutationFn: () =>
      subscriptionsApi.create({
        userId: selected!.id,
        // Пусто — из настроек панели, 0 — без ограничения (как при выдаче ключа).
        ...(expiryDays === '' ? {} : { expiryDays: Number(expiryDays) }),
        ...(trafficLimitGb === '' ? {} : { trafficLimitBytes: Math.round(Number(trafficLimitGb) * BYTES_IN_GB) }),
      }),
    onSuccess: onDone,
  });

  const defaultExpiry = settings.data?.defaultExpiryDays;
  const defaultTraffic = settings.data?.defaultTrafficLimitBytes;
  const invalid =
    !selected ||
    (expiryDays !== '' && !(Number(expiryDays) >= 0)) ||
    (trafficLimitGb !== '' && !(Number(trafficLimitGb) >= 0));

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!invalid) create.mutate();
  }

  return (
    <Dialog
      title="Новая подписка"
      onClose={onClose}
      closeDisabled={create.isPending}
      actions={
        <>
          <Btn variant="secondary" onClick={onClose} disabled={create.isPending}>Закрыть</Btn>
          <Btn variant="primary" onClick={() => create.mutate()} disabled={create.isPending || invalid}>
            {create.isPending ? 'Создаём…' : 'Создать'}
          </Btn>
        </>
      }
    >
      <form className={styles.dialogForm} onSubmit={submit} aria-busy={create.isPending}>
        <div className="field">
          <label htmlFor="sub-user-search">Пользователь</label>
          <input
            id="sub-user-search"
            className="input"
            type="search"
            data-dialog-initial-focus
            placeholder="Имя, логин или контакт"
            value={userSearch}
            disabled={create.isPending}
            onChange={(event) => setUserSearch(event.target.value)}
          />
          <p className={styles.hint}>
            Подписку получает существующий пользователь. Активная подписка у пользователя может быть только одна.
          </p>

          {term.length < USER_SEARCH_MIN ? null : users.isPending ? (
            <Spinner />
          ) : users.isError ? (
            <ErrorBanner message="Не удалось найти пользователей." onRetry={() => void users.refetch()} />
          ) : users.data.items.length === 0 ? (
            <p className={styles.hint} role="status">Никого не найдено.</p>
          ) : (
            <div className={styles.userList} role="radiogroup" aria-label="Найденные пользователи">
              {users.data.items.map((user) => (
                <label
                  key={user.id}
                  className={user.id === selected?.id ? `${styles.userRow} ${styles.userRowActive}` : styles.userRow}
                >
                  <input
                    type="radio"
                    name="subscription-user"
                    checked={user.id === selected?.id}
                    disabled={create.isPending}
                    onChange={() => setSelected(user)}
                  />
                  <span className={styles.userInfo}>
                    <span className={styles.userName}>{user.displayName ?? user.username}</span>
                    <span className={styles.userMeta}>{joinMeta(user.username, user.contact)}</span>
                  </span>
                </label>
              ))}
            </div>
          )}

          {selected ? (
            <p className={styles.hint} role="status">Выбран: {selected.displayName ?? selected.username}</p>
          ) : null}
        </div>

        <div className="field">
          <label htmlFor="sub-expiry">Срок действия, дней</label>
          <input
            id="sub-expiry"
            className={styles.narrow}
            type="number"
            min={0}
            placeholder={defaultExpiry ? String(defaultExpiry) : 'бессрочно'}
            value={expiryDays}
            disabled={create.isPending}
            onChange={(event) => setExpiryDays(event.target.value)}
          />
          <p className={styles.hint}>Пусто — как в настройках панели, 0 — бессрочно.</p>
        </div>

        <div className="field">
          <label htmlFor="sub-traffic">Лимит трафика, ГБ</label>
          <input
            id="sub-traffic"
            className={styles.narrow}
            type="number"
            min={0}
            placeholder={defaultTraffic ? String(defaultTraffic / BYTES_IN_GB) : 'без ограничения'}
            value={trafficLimitGb}
            disabled={create.isPending}
            onChange={(event) => setTrafficLimitGb(event.target.value)}
          />
          <p className={styles.hint}>
            Пусто — как в настройках панели, 0 — без ограничения. По исчерпании подписка отзывается автоматически.
          </p>
        </div>

        {create.isError ? <ErrorBanner message={errorMessage(create.error, 'Не удалось создать подписку.')} /> : null}
      </form>
    </Dialog>
  );
}

// ── Ссылка ───────────────────────────────────────────────────────────────────

function LinkDialog({ subscription, onClose }: { subscription: SubscriptionListItem; onClose: () => void }) {
  const { show } = useToast();

  // Ссылка — учётные данные: в кеше запросов она не задерживается (gcTime 0), не перезапрашивается
  // сама по фокусу окна и не повторяется при ошибке, пока оператор не нажмёт «Повторить».
  const link = useQuery({
    queryKey: qk.subscriptionLink(subscription.id),
    queryFn: () => subscriptionsApi.link(subscription.id),
    gcTime: 0,
    staleTime: 0,
    retry: false,
    refetchOnWindowFocus: false,
  });

  async function copy() {
    if (!link.data) return;

    try {
      await navigator.clipboard.writeText(link.data.url);
      show('Ссылка скопирована');
    } catch {
      show('Не удалось скопировать ссылку');
    }
  }

  return (
    <Dialog
      title={`Ссылка подписки: ${subscription.userName ?? 'пользователь'}`}
      onClose={onClose}
      actions={
        <>
          {link.data ? (
            <Btn variant="primary" onClick={() => void copy()}>Скопировать ссылку</Btn>
          ) : null}
          <Btn variant="secondary" onClick={onClose}>Закрыть</Btn>
        </>
      }
    >
      {link.isPending ? <Spinner label="Загружаем ссылку…" /> : link.isError ? (
        <ErrorBanner
          message={errorMessage(link.error, 'Не удалось получить ссылку подписки.')}
          onRetry={() => void link.refetch()}
        />
      ) : (
        <div className="field">
          <label htmlFor="sub-link">Ссылка для приложения Happ</label>
          <textarea
            id="sub-link"
            className={`input ${styles.linkArea}`}
            readOnly
            rows={3}
            data-dialog-initial-focus
            value={link.data.url}
          />
          <p className={styles.warning}>Ссылку не пересылайте: по ней подключается любой.</p>
        </div>
      )}
    </Dialog>
  );
}

// ── Лимиты ───────────────────────────────────────────────────────────────────

/** Дата в формате поля type="date" в часовом поясе оператора. */
function toDateInput(iso: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

function LimitsDialog({
  subscription,
  onClose,
  onDone,
}: {
  subscription: SubscriptionListItem;
  onClose: () => void;
  onDone: () => void;
}) {
  const initialDate = toDateInput(subscription.expiresAt);
  const initialGb = subscription.trafficLimitBytes ? String(subscription.trafficLimitBytes / BYTES_IN_GB) : '';
  const [date, setDate] = useState(initialDate);
  const [limitGb, setLimitGb] = useState(initialGb);

  // Конец выбранного дня: срок «до 31.12» включает 31 декабря. Нетронутое поле отправляем как было —
  // иначе открытие окна и «Сохранить» сдвинуло бы время окончания на конец суток.
  const expiresAt = date === '' ? null : date === initialDate ? subscription.expiresAt : new Date(`${date}T23:59:59`).toISOString();
  const trafficLimitBytes =
    limitGb === '' || Number(limitGb) === 0
      ? null
      : limitGb === initialGb ? subscription.trafficLimitBytes : Math.round(Number(limitGb) * BYTES_IN_GB);

  const expiryInPast = expiresAt !== null && new Date(expiresAt).getTime() <= Date.now();
  const limitInvalid = limitGb !== '' && !(Number(limitGb) >= 0);

  const save = useMutation({
    mutationFn: () => subscriptionsApi.updateLimits(subscription.id, { expiresAt, trafficLimitBytes }),
    onSuccess: onDone,
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!expiryInPast && !limitInvalid) save.mutate();
  }

  return (
    <Dialog
      title={`Срок и лимит: ${subscription.userName ?? 'пользователь'}`}
      onClose={onClose}
      closeDisabled={save.isPending}
      actions={
        <>
          <Btn variant="secondary" onClick={onClose} disabled={save.isPending}>Закрыть</Btn>
          <Btn
            variant="primary"
            onClick={() => save.mutate()}
            disabled={save.isPending || expiryInPast || limitInvalid}
          >
            {save.isPending ? 'Сохраняем…' : 'Сохранить'}
          </Btn>
        </>
      }
    >
      <form className={styles.dialogForm} onSubmit={submit} aria-busy={save.isPending}>
        <div className="field">
          <label htmlFor="sub-expires">Действует до</label>
          <input
            id="sub-expires"
            className={styles.narrow}
            type="date"
            data-dialog-initial-focus
            value={date}
            disabled={save.isPending}
            onChange={(event) => setDate(event.target.value)}
          />
          <p className={styles.hint}>Пусто — бессрочно. Дата включительно.</p>
          {expiryInPast ? <p className={styles.warning} role="alert">Срок должен быть в будущем.</p> : null}
        </div>

        <div className="field">
          <label htmlFor="sub-limit">Лимит трафика, ГБ</label>
          <input
            id="sub-limit"
            className={styles.narrow}
            type="number"
            min={0}
            step="any"
            value={limitGb}
            disabled={save.isPending}
            onChange={(event) => setLimitGb(event.target.value)}
          />
          <p className={styles.hint}>Пусто или 0 — без ограничения. Израсходованный трафик не сбрасывается.</p>
        </div>

        {save.isError ? <ErrorBanner message={errorMessage(save.error, 'Не удалось сохранить границы.')} /> : null}
      </form>
    </Dialog>
  );
}
