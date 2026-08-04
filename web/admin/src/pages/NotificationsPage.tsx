import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { notifications as notificationsApi, type CreateNotificationBody } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { NotificationCampaign, NotificationCampaignStatus } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ConfirmDialog } from '@/components/Dialog';
import { EmptyState, ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { useToast } from '@/components/Toast';
import { formatLogTime, formatNumber } from '@/lib/format';
import type { TagTone } from '@/lib/labels';
import styles from './NotificationsPage.module.css';

const STATUS: Record<NotificationCampaignStatus, { label: string; tone: TagTone }> = {
  queued: { label: 'в очереди', tone: 'outline' },
  running: { label: 'отправляется', tone: 'accent' },
  completed: { label: 'завершена', tone: 'neutral' },
  canceled: { label: 'остановлена', tone: 'outline' },
  failed: { label: 'ошибка', tone: 'accent' },
};

export function NotificationsPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const { show } = useToast();
  const isAdmin = can('panel:admin');
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [silent, setSilent] = useState(false);
  const [pendingCreate, setPendingCreate] = useState<CreateNotificationBody | null>(null);
  const [pendingCancel, setPendingCancel] = useState<NotificationCampaign | null>(null);

  const audience = useQuery({
    queryKey: qk.notificationAudience,
    queryFn: notificationsApi.audience,
    enabled: isAdmin,
  });
  const campaigns = useQuery({
    queryKey: qk.notificationList({ pageSize: 50 }),
    queryFn: () => notificationsApi.list({ pageSize: 50 }),
    enabled: isAdmin,
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => item.status === 'queued' || item.status === 'running')
        ? 3000
        : false,
  });
  const create = useMutation({
    mutationFn: (body: CreateNotificationBody) => notificationsApi.create(body),
    onSuccess: () => {
      setPendingCreate(null);
      setTitle('');
      setText('');
      setSilent(false);
      void queryClient.invalidateQueries({ queryKey: qk.notifications });
      show('Рассылка поставлена в очередь');
    },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => notificationsApi.cancel(id),
    onSuccess: () => {
      setPendingCancel(null);
      void queryClient.invalidateQueries({ queryKey: qk.notifications });
      show('Рассылка остановлена');
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    const body = { title: title.trim() || undefined, text: text.trim(), disableNotification: silent };
    if (body.text.length > 0) setPendingCreate(body);
  }

  if (!isAdmin) return <ErrorBanner message="У вас нет прав на управление рассылками." />;

  const recipientCount = audience.data?.recipientCount ?? 0;
  return <>
    <PageHeader kicker="Клиенты" title="Рассылки" />

    <form className={styles.composer} onSubmit={submit} aria-busy={create.isPending}>
      <div className="field">
        <label htmlFor="notification-title">Название для журнала</label>
        <input id="notification-title" className="input" maxLength={128} value={title} disabled={create.isPending} onChange={(event) => setTitle(event.target.value)} placeholder="Например, Технические работы" />
      </div>
      <div className="field">
        <label htmlFor="notification-text">Сообщение</label>
        <textarea id="notification-text" className="input" rows={7} maxLength={4096} required value={text} disabled={create.isPending} onChange={(event) => setText(event.target.value)} placeholder="Текст, который получат пользователи бота" />
        <span className={styles.counter}>{formatNumber(text.length)} / 4 096</span>
      </div>
      <label className={styles.checkbox}>
        <input type="checkbox" checked={silent} disabled={create.isPending} onChange={(event) => setSilent(event.target.checked)} />
        Отправить без звукового уведомления
      </label>
      <div className={styles.composeFooter}>
        <span className={styles.audience}>
          {audience.isPending ? 'Считаем получателей…' : `Получателей: ${formatNumber(recipientCount)}`}
        </span>
        <Btn variant="primary" type="submit" disabled={create.isPending || audience.isPending || recipientCount === 0 || text.trim().length === 0}>
          Подготовить рассылку
        </Btn>
      </div>
    </form>

    {create.isError ? <ErrorBanner message={errorMessage(create.error, 'Не удалось создать рассылку.')} /> : null}
    {cancel.isError ? <ErrorBanner message={errorMessage(cancel.error, 'Не удалось остановить рассылку.')} /> : null}
    {audience.isError ? <ErrorBanner message="Не удалось определить число получателей." onRetry={() => void audience.refetch()} /> : null}

    <section className={styles.history} aria-labelledby="notification-history-title">
      <h3 id="notification-history-title">История</h3>
      {campaigns.isPending ? <Spinner /> : campaigns.isError ? <ErrorBanner message="Не удалось загрузить рассылки." onRetry={() => void campaigns.refetch()} /> : campaigns.data?.items.length ? <div className={styles.list}>
        {campaigns.data.items.map((campaign) => {
          const done = campaign.sentCount + campaign.failedCount + campaign.skippedCount;
          const percent = campaign.totalCount > 0 ? Math.round(done * 100 / campaign.totalCount) : 100;
          return <article className={styles.card} key={campaign.id}>
            <div className={styles.cardHeader}>
              <div>
                <h4>{campaign.title}</h4>
                <span className={styles.meta}>{formatLogTime(campaign.createdAt)}{campaign.disableNotification ? ' · без звука' : ''}</span>
              </div>
              <StatusTag status={STATUS[campaign.status]} />
            </div>
            <p className={styles.preview}>{campaign.text}</p>
            <progress className={styles.progress} max={100} value={percent}>{percent}%</progress>
            <div className={styles.stats}>
              <span>Отправлено: {formatNumber(campaign.sentCount)}</span>
              <span>Ошибки: {formatNumber(campaign.failedCount)}</span>
              <span>Пропущено: {formatNumber(campaign.skippedCount)}</span>
              <span>Всего: {formatNumber(campaign.totalCount)}</span>
            </div>
            {campaign.error ? <p className={styles.error}>{campaign.error}</p> : null}
            {campaign.status === 'queued' || campaign.status === 'running' ? <div className={styles.cardActions}><Btn variant="ghost" disabled={cancel.isPending} onClick={() => setPendingCancel(campaign)}>Остановить</Btn></div> : null}
          </article>;
        })}
      </div> : <EmptyState title="Рассылок пока нет" hint="Подготовьте сообщение выше — отправка начнётся только после подтверждения." />}
    </section>

    {pendingCreate ? <ConfirmDialog title="Начать рассылку?" body={`Сообщение будет поставлено в очередь для ${formatNumber(recipientCount)} пользователей. После запуска изменить текст нельзя.`} confirmLabel="Начать рассылку" busy={create.isPending} onConfirm={() => create.mutate(pendingCreate)} onCancel={() => setPendingCreate(null)} /> : null}
    {pendingCancel ? <ConfirmDialog title={`Остановить «${pendingCancel.title}»?`} body="Уже доставленные сообщения останутся у пользователей. Задания, которые ещё не отправлены, будут отменены." confirmLabel="Остановить" busy={cancel.isPending} onConfirm={() => cancel.mutate(pendingCancel.id)} onCancel={() => setPendingCancel(null)} /> : null}
  </>;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}
