import { useEffect, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { settings as settingsApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { DefRow, ErrorBanner, SectionTitle } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { Tag } from '@/components/Tag';
import { BYTES_IN_GB, formatBytes, plural } from '@/lib/format';
import { ProtocolDisplay } from '@/lib/protocols';
import styles from './SettingsPage.module.css';

export function SettingsPage() {
  const query = useQuery({ queryKey: qk.settings, queryFn: settingsApi.get });
  const queryClient = useQueryClient();
  const { can } = useAuth();
  const [expiryDays, setExpiryDays] = useState('');
  const [trafficLimitGb, setTrafficLimitGb] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!query.data) return;
    setExpiryDays(query.data.defaultExpiryDays?.toString() ?? '');
    setTrafficLimitGb(
      query.data.defaultTrafficLimitBytes === null
        ? ''
        : String(query.data.defaultTrafficLimitBytes / BYTES_IN_GB),
    );
  }, [query.data]);

  const update = useMutation({
    mutationFn: () => settingsApi.update({
      defaultExpiryDays: expiryDays === '' ? null : Number(expiryDays),
      defaultTrafficLimitBytes: trafficLimitGb === '' ? null : Math.round(Number(trafficLimitGb) * BYTES_IN_GB),
    }),
    onSuccess: (settings) => {
      queryClient.setQueryData(qk.settings, settings);
      void queryClient.invalidateQueries({ queryKey: qk.settings });
      setSaved(true);
    },
  });

  if (query.isPending) return <Spinner />;
  if (query.isError || !query.data) {
    return <ErrorBanner message="Не удалось загрузить настройки." onRetry={() => void query.refetch()} />;
  }

  const s = query.data;
  const isAdmin = can('panel:admin');

  function submit(event: FormEvent) {
    event.preventDefault();
    if (update.isPending) return;
    setSaved(false);
    update.mutate();
  }

  return (
    <>
      <PageHeader kicker="Система" title="Настройки панели" />

      <div className={styles.columns}>
        <section>
          <SectionTitle>Выдача ключей по умолчанию</SectionTitle>

          <DefRow label="Срок действия">
            {s.defaultExpiryDays
              ? `${s.defaultExpiryDays} ${plural(s.defaultExpiryDays, 'день', 'дня', 'дней')}`
              : 'бессрочно'}
          </DefRow>
          <DefRow label="Лимит устройств">
            {s.deviceLimitPerClient ?? 'без ограничения'}
          </DefRow>
          <DefRow label="Протокол по умолчанию">
            {ProtocolDisplay[s.defaultProtocolKind] ?? s.defaultProtocolKind}
          </DefRow>
          <DefRow label="Лимит трафика">
            {s.defaultTrafficLimitBytes ? formatBytes(s.defaultTrafficLimitBytes) : 'без лимита'}
          </DefRow>

          {isAdmin ? <form className={styles.form} onSubmit={submit} aria-busy={update.isPending}>
            <div className={styles.editGrid}>
              <div className="field">
                <label htmlFor="default-expiry-days">Срок по умолчанию, дней</label>
                <input
                  id="default-expiry-days"
                  className="input"
                  type="number"
                  min={1}
                  max={3650}
                  step={1}
                  value={expiryDays}
                  disabled={update.isPending}
                  onChange={(event) => { setSaved(false); setExpiryDays(event.target.value); }}
                />
                <p className={styles.hint}>Пусто — новые ключи бессрочные. От 1 до 3650 дней.</p>
              </div>
              <div className="field">
                <label htmlFor="default-traffic-limit">Лимит трафика, ГиБ</label>
                <input
                  id="default-traffic-limit"
                  className="input"
                  type="number"
                  min="0.001"
                  max={10240}
                  step="0.001"
                  value={trafficLimitGb}
                  disabled={update.isPending}
                  onChange={(event) => { setSaved(false); setTrafficLimitGb(event.target.value); }}
                />
                <p className={styles.hint}>Пусто — без лимита. Сервер принимает от 1 МиБ до 10 ТиБ.</p>
              </div>
            </div>
            {update.isError ? <ErrorBanner message={settingsError(update.error)} /> : null}
            {saved ? <p className={styles.success} role="status">Настройки сохранены и будут применены к следующим ключам.</p> : null}
            <div className={styles.formActions}>
              <Btn variant="primary" type="submit" disabled={update.isPending}>
                {update.isPending ? 'Сохраняем…' : 'Сохранить настройки'}
              </Btn>
            </div>
          </form> : <p className={styles.readOnly}>Только владелец и администраторы могут менять параметры выдачи.</p>}
        </section>

        <section className={styles.right}>
          <SectionTitle>Безопасность</SectionTitle>

          <div className={styles.toggleRow}>
            <div>
              <div className={styles.toggleTitle}>Секреты скрыты в интерфейсе</div>
              <div className={styles.toggleHint}>
                Приватный ключ доступен только в момент выдачи и не хранится в открытом виде
              </div>
            </div>
            <Tag tone="neutral">не применяется</Tag>
          </div>

          <div className={styles.toggleRow}>
            <div>
              <div className={styles.toggleTitle}>Двухфакторный вход в панель</div>
              <div className={styles.toggleHint}>TOTP пока не реализован и этот параметр не применяется</div>
            </div>
            <Tag tone="neutral">выключено</Tag>
          </div>

          <DefRow label="Уведомления о падении узла">
            {s.alertTelegramChat ?? 'не настроены'}
          </DefRow>
          <p className={styles.readOnly}>
            Лимит устройств, протокол по умолчанию, маскирование, 2FA и Telegram-уведомления
            пока не имеют обработчика runtime и здесь не редактируются.
          </p>
        </section>
      </div>
    </>
  );
}

function settingsError(error: unknown): string {
  return error instanceof ApiError ? error.message : 'Не удалось сохранить настройки.';
}
