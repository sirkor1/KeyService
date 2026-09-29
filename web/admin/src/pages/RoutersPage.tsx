import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { routerKeys, routersApi, type RouterMonitor, type RouterSettings, type RouterState } from '@/api/routers';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ConfirmDialog } from '@/components/Dialog';
import { ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { useToast } from '@/components/Toast';
import { formatLogTime } from '@/lib/format';
import type { TagTone } from '@/lib/labels';
import styles from './RoutersPage.module.css';

const states: Record<RouterState, { label: string; tone: TagTone }> = {
  waiting: { label: 'Ожидает подключения', tone: 'outline' },
  online: { label: 'На связи', tone: 'neutral' },
  offline: { label: 'Нет связи', tone: 'accent' },
  unknown: { label: 'Нет данных', tone: 'outline' },
  setup: { label: 'Требуется настройка', tone: 'accent' },
  paused: { label: 'На паузе', tone: 'outline' },
};
const deliveries: Record<string, string> = {
  pending: 'В очереди', sending: 'Отправляется', sent: 'Отправлено', failed: 'Ошибка доставки', skipped: 'Без уведомления',
};
const time = (value: string | null) => value ? formatLogTime(value) : 'Ещё нет данных';
const errorText = (error: Error) => error.message || 'Не удалось выполнить действие.';

export function RoutersPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const query = useQuery({ queryKey: routerKeys.list, queryFn: routersApi.list, refetchInterval: 15000 });
  const items = (query.data ?? []).filter(r => `${r.name} ${r.userName ?? ''} ${r.telegramId ?? ''}`.toLowerCase().includes(search.toLowerCase()));
  return <>
    <PageHeader kicker="Наблюдение" title="Роутеры" actions={can('panel:admin') ? <Btn variant="primary" onClick={() => navigate('/routers/add')}>Добавить роутер</Btn> : undefined} />
    <p className={styles.notice}>Наблюдение за связью с домом. Потеря соединения может означать отключение электричества или интернета.</p>
    <div className={`field ${styles.filters}`}><label htmlFor="router-search">Поиск по названию, пользователю или Telegram ID</label>
      <input id="router-search" className="input" value={search} onChange={e => setSearch(e.target.value)} /></div>
    {query.isPending ? <Spinner /> : query.isError ? <ErrorBanner message={errorText(query.error)} onRetry={() => void query.refetch()} /> :
      <div className={styles.grid}>
        {!items.length && <p>{query.data?.length ? 'По вашему запросу ничего не найдено.' : 'Роутеров пока нет. Добавьте роутер и выберите получателя уведомлений.'}</p>}
        {items.map(r => <article className={styles.card} key={r.id}>
          <div className={styles.row}><h3><Link to={`/routers/${r.id}`}>{r.name}</Link></h3><StatusTag status={states[r.state]} /></div>
          <p>{r.userName ?? 'Пользователь удалён'} · Telegram {r.telegramId ?? 'не привязан'}</p>
          <p className={styles.meta}>Последний handshake: {time(r.lastHandshakeAt)} · {r.serverName ?? 'Узел удалён'}</p>
          <p className={styles.meta}>Уведомления {r.notificationsEnabled ? 'включены' : 'выключены'}{!r.recipientAvailable ? ' · получатель недоступен' : ''}</p>
        </article>)}
      </div>}
  </>;
}

export function AddRouterPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const cache = useQueryClient();
  const [name, setName] = useState('');
  const [userId, setUserId] = useState('');
  const [serverId, setServerId] = useState('');
  const [protocolId, setProtocolId] = useState('');
  const options = useQuery({ queryKey: routerKeys.options, queryFn: routersApi.options, enabled: can('panel:admin') });
  const server = options.data?.servers.find(s => s.id === serverId);
  const selectedProtocol = server?.protocols.find(p => p.id === protocolId)?.id ?? server?.protocols[0]?.id ?? '';
  const create = useMutation({ mutationFn: () => routersApi.create({ name: name.trim(), userId, serverId, protocolId: selectedProtocol }),
    onSuccess: r => { void cache.invalidateQueries({ queryKey: routerKeys.all }); navigate(`/routers/${r.id}`); } });
  if (!can('panel:admin')) return <ErrorBanner message="Добавлять роутеры может администратор." />;
  function submit(e: FormEvent) { e.preventDefault(); create.mutate(); }
  return <>
    <PageHeader kicker="Наблюдение" title="Добавить роутер" back={{ to: '/routers', label: 'Все роутеры' }} />
    {options.isPending ? <Spinner /> : options.isError ? <ErrorBanner message={errorText(options.error)} onRetry={() => void options.refetch()} /> :
      <form className={styles.form} onSubmit={submit} aria-busy={create.isPending}>
        <div className="field"><label htmlFor="router-name">Название</label><input id="router-name" className="input" required maxLength={100} value={name} onChange={e => setName(e.target.value)} placeholder="Дом" /></div>
        <div className="field"><label htmlFor="router-user">Пользователь Telegram</label><select id="router-user" className="input" required value={userId} onChange={e => setUserId(e.target.value)}>
          <option value="">Выберите получателя</option>{options.data?.users.map(u => <option key={u.id} value={u.id}>{u.name} · {u.telegramId}</option>)}
        </select><span className={styles.meta}>Пользователь должен зарегистрироваться в боте по пригласительному коду.</span></div>
        <div className="field"><label htmlFor="router-server">VPN-узел</label><select id="router-server" className="input" required value={serverId} onChange={e => { setServerId(e.target.value); setProtocolId(''); }}>
          <option value="">Выберите сервер с WireGuard</option>{options.data?.servers.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>{!options.data?.servers.length && <span>Нет доступного обычного WireGuard. Добавьте протокол в <Link to="/servers">карточке сервера</Link>.</span>}</div>
        {(server?.protocols.length ?? 0) > 1 && <div className="field"><label htmlFor="router-protocol">Подключение WireGuard</label><select id="router-protocol" className="input" value={selectedProtocol} onChange={e => setProtocolId(e.target.value)}>{server?.protocols.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></div>}
        <p className={styles.meta}>Будет создан отдельный бессрочный ключ без квоты. После создания скачайте профиль в карточке и импортируйте его в роутер.</p>
        {create.isError && <ErrorBanner message={errorText(create.error)} />}
        <Btn variant="primary" type="submit" disabled={create.isPending || !userId || !selectedProtocol || !name.trim()}>{create.isPending ? 'Создаём…' : 'Создать подключение'}</Btn>
      </form>}
  </>;
}

export function RouterDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const [tab, setTab] = useState('overview');
  const [confirm, setConfirm] = useState(false);
  const navigate = useNavigate();
  const cache = useQueryClient();
  const { show } = useToast();
  const query = useQuery({ queryKey: routerKeys.detail(id), queryFn: () => routersApi.get(id), refetchInterval: 15000 });
  const history = useQuery({ queryKey: routerKeys.history(id), queryFn: () => routersApi.history(id), refetchInterval: 15000 });
  const test = useMutation({ mutationFn: () => routersApi.test(id), onSuccess: () => { show('Тест поставлен в очередь'); void cache.invalidateQueries({ queryKey: routerKeys.history(id) }); } });
  const download = useMutation({ mutationFn: () => routersApi.config(id), onSuccess: file => {
    const url = URL.createObjectURL(new Blob([file.content], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a'); a.href = url; a.download = file.fileName; a.click(); URL.revokeObjectURL(url);
    show('Профиль роутера скачан');
  } });
  const archive = useMutation({ mutationFn: () => routersApi.archive(id), onSuccess: () => {
    void cache.invalidateQueries({ queryKey: routerKeys.all }); navigate('/routers');
  } });
  if (query.isPending) return <Spinner />;
  if (query.isError) return <ErrorBanner message={errorText(query.error)} onRetry={() => void query.refetch()} />;
  const r = query.data;
  return <>
    <PageHeader kicker="Наблюдение" title={r.name} back={{ to: '/routers', label: 'Все роутеры' }} badge={<StatusTag status={states[r.state]} />} />
    <nav className={styles.tabs} aria-label="Разделы карточки роутера">
      {([['overview', 'Обзор'], ['connection', 'Подключение'], ['notifications', 'Уведомления и настройки']] as const).map(([value, label]) =>
        <Btn key={value} variant={tab === value ? 'primary' : 'secondary'} aria-pressed={tab === value} onClick={() => setTab(value)}>{label}</Btn>)}
    </nav>
    {tab === 'overview' && <>
      <section className={styles.card} aria-label="Состояние наблюдения"><dl className={styles.facts}>
        <div><dt>Последнее подтверждение связи</dt><dd>{time(r.lastHandshakeAt)}</dd></div>
        <div><dt>Последняя проверка</dt><dd>{time(r.lastCheckedAt)}</dd></div>
        <div><dt>Получатель</dt><dd>{r.userName ?? 'Пользователь удалён'} · {r.telegramId ?? 'Telegram не привязан'}</dd></div>
        <div><dt>Порог возраста handshake</dt><dd>{Math.round(r.offlineAfterSeconds / 60)} мин.</dd></div>
      </dl>{r.detail && <p>{r.detail}</p>}</section>
      <p className={styles.notice}>Время отключения приблизительное. «Нет данных» означает перерыв в наблюдении, а не отключение электричества. Короткие перебои могут остаться незамеченными.</p>
    </>}
    {tab === 'connection' && <section className={styles.card}>
      <h3>Подключение TP-Link</h3><p>Узел: <Link to={`/servers/${r.serverId}`}>{r.serverName ?? r.serverId}</Link></p>
      <p><Link to={`/keys?search=${encodeURIComponent(r.keyId)}`}>Выделенный ключ роутера</Link> · бессрочный, без квоты</p>
      <ol className={styles.steps}>
        <li>Скачайте файл .conf. Если ключ ещё готовится, повторите через полминуты.</li>
        <li>Откройте VPN-клиент → Добавить → WireGuard и загрузите файл.</li>
        <li>Оставьте NAT включённым, VPN Kill Switch выключите. Сохраните и включите профиль.</li>
        <li>Дождитесь состояния «На связи». Проверьте соединение без подключённых домашних устройств и после перезапуска роутера.</li>
      </ol><p className={styles.meta}>Профиль включает keepalive 25 секунд и маршрут только к VPN-адресу узла. Домашний интернет через VPS не перенаправляется.</p>
      {can('panel:admin') && <Btn variant="primary" disabled={download.isPending} onClick={() => download.mutate()}>Скачать .conf</Btn>}
      {download.isError && <ErrorBanner message={errorText(download.error)} />}
      {r.state === 'setup' && <p>Проверьте ключ в разделе «Ключи» и журнал событий. После прерванной выдачи проверьте узел перед повторным созданием подключения.</p>}
    </section>}
    {tab === 'notifications' && <>
      {!r.recipientAvailable && <ErrorBanner message="Получатель недоступен. Выберите активного пользователя Telegram." />}
      {can('panel:admin') ? <RouterSettingsForm key={`${r.id}-${r.deliveryGeneration}`} router={r} /> : <p>Изменять настройки может администратор.</p>}
      {can('panel:admin') && <div className={styles.actions}>
        <Btn variant="secondary" disabled={test.isPending || !r.recipientAvailable} onClick={() => test.mutate()}>Тестовое сообщение</Btn>
        <Btn variant="ghost" onClick={() => setConfirm(true)}>Удалить наблюдение</Btn>
      </div>}
      {test.isError && <ErrorBanner message={errorText(test.error)} />}
    </>}
    <section className={styles.history} aria-labelledby="router-history-title"><h3 id="router-history-title">История · последние 100 событий</h3>
      {history.isPending ? <Spinner /> : history.isError ? <ErrorBanner message={errorText(history.error)} onRetry={() => void history.refetch()} /> :
        <div className={styles.grid}>{!history.data?.length && <p>Событий пока нет.</p>}{history.data?.map(h => <article className={styles.card} key={h.id}>
          <div className={styles.row}><strong>{h.state === 'test' ? 'Тест уведомлений' : states[h.state].label}</strong><span className={styles.meta}>{time(h.at)}</span></div>
          {h.detail && <p>{h.detail}</p>}{h.outageSeconds !== null && <p>Наблюдаемый перерыв: около {Math.ceil(h.outageSeconds / 60)} мин.</p>}
          <p className={styles.meta}>{deliveries[h.deliveryStatus] ?? h.deliveryStatus}{h.sentAt ? ` · ${time(h.sentAt)}` : ''}</p>
          {h.deliveryError && <p className={h.deliveryStatus === 'failed' ? styles.error : styles.meta}>{h.deliveryError}</p>}
        </article>)}</div>}
    </section>
    {confirm && <ConfirmDialog title="Удалить наблюдение?" body={<><p>История сохранится. VPN-ключ останется действующим — при необходимости отзовите его отдельно в разделе «Ключи».</p>{archive.isError && <ErrorBanner message={errorText(archive.error)} />}</>} confirmLabel="Удалить наблюдение" busy={archive.isPending} onCancel={() => setConfirm(false)} onConfirm={() => archive.mutate()} />}
  </>;
}

function RouterSettingsForm({ router }: { router: RouterMonitor }) {
  const [draft, setDraft] = useState<RouterSettings>({ name: router.name, userId: router.userId, paused: router.paused,
    notificationsEnabled: router.notificationsEnabled, offlineAfterSeconds: router.offlineAfterSeconds, deliveryGeneration: router.deliveryGeneration });
  const options = useQuery({ queryKey: routerKeys.options, queryFn: routersApi.options });
  const cache = useQueryClient();
  const { show } = useToast();
  const update = useMutation({ mutationFn: () => routersApi.update(router.id, draft), onSuccess: () => {
    show('Настройки сохранены'); void cache.invalidateQueries({ queryKey: routerKeys.all });
  } });
  function submit(e: FormEvent) { e.preventDefault(); update.mutate(); }
  return <form className={styles.form} onSubmit={submit} aria-busy={update.isPending}>
    <div className="field"><label htmlFor="router-edit-name">Название</label><input id="router-edit-name" className="input" required maxLength={100} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} /></div>
    <div className="field"><label htmlFor="router-edit-user">Получатель Telegram</label><select id="router-edit-user" className="input" value={draft.userId} onChange={e => setDraft({ ...draft, userId: e.target.value })}>
      {!options.data?.users.some(u => u.id === router.userId) && <option value={router.userId}>{router.userName ?? 'Текущий получатель'} · недоступен</option>}
      {options.data?.users.map(u => <option key={u.id} value={u.id}>{u.name} · {u.telegramId}</option>)}
    </select></div>
    {options.isError && <ErrorBanner message={errorText(options.error)} onRetry={() => void options.refetch()} />}
    <div className="field"><label htmlFor="router-threshold">Порог возраста handshake, секунды</label><input id="router-threshold" className="input" type="number" required min={180} max={3600} value={draft.offlineAfterSeconds} onChange={e => setDraft({ ...draft, offlineAfterSeconds: Number(e.target.value) })} /><span className={styles.meta}>Рекомендуется 240. Это не точная длительность отключения.</span></div>
    <label className={styles.checkbox}><input type="checkbox" checked={draft.notificationsEnabled} onChange={e => setDraft({ ...draft, notificationsEnabled: e.target.checked })} />Уведомлять о потере и восстановлении связи</label>
    <label className={styles.checkbox}><input type="checkbox" checked={draft.paused} onChange={e => setDraft({ ...draft, paused: e.target.checked })} />Приостановить наблюдение</label>
    <p className={styles.meta}>При отключённых уведомлениях история продолжается. На паузе перерывы связи не учитываются. Смена получателя отменяет ещё не отправленные сообщения прежнему пользователю.</p>
    {update.isError && <ErrorBanner message={errorText(update.error)} />}
    <Btn variant="primary" type="submit" disabled={update.isPending || options.isPending}>Сохранить</Btn>
  </form>;
}
