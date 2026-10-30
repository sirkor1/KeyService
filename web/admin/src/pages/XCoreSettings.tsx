import { useId, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { servers, type XCoreSettingsBody } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { ServerDetail, XCoreInfo } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ErrorBanner } from '@/components/Misc';
import { Tag } from '@/components/Tag';
import { formatLogTime } from '@/lib/format';
import styles from './XCoreSettings.module.css';

/** Максимальная длина названия подключения в приложении Happ. */
const TITLE_MAX_LENGTH = 30;

/**
 * Поля формы. Текстовые списки хранятся строкой с переводами строк, как их вводит оператор;
 * числа — строкой, чтобы пустое поле не превращалось в ноль.
 */
interface FormState {
  title: string;
  sortOrder: string;
  subscriptionEnabled: boolean;
  ruDirect: boolean;
  directDomains: string;
  proxyDomains: string;
  subscriptionHost: string;
  vlessEncryption: boolean;
}

/** Сервер хранит домены с префиксом domain:; оператору показывается то, что он вводил — голое имя. */
const showDomain = (entry: string) => (entry.startsWith('domain:') ? entry.slice('domain:'.length) : entry);

function toState(info: XCoreInfo): FormState {
  return {
    title: info.title ?? '',
    sortOrder: String(info.sortOrder),
    subscriptionEnabled: info.subscriptionEnabled,
    ruDirect: info.ruDirect,
    directDomains: info.directDomains.map(showDomain).join('\n'),
    proxyDomains: info.proxyDomains.map(showDomain).join('\n'),
    subscriptionHost: info.subscriptionHost ?? '',
    vlessEncryption: info.vlessEncryption,
  };
}

const lines = (text: string) => text.split('\n').map((line) => line.trim()).filter(Boolean);

type FieldName = keyof FormState;
const FIELDS: FieldName[] = [
  'title', 'sortOrder', 'subscriptionEnabled', 'ruDirect', 'directDomains', 'proxyDomains', 'subscriptionHost',
  'vlessEncryption',
];

/**
 * Настройки подписочного узла. Показываются администратору: PUT доступен только ему. Роль, домен узла и
 * ключи здесь не меняются — они задаются при установке.
 */
export function XCoreSettings({ serverId, protocolId, info }: { serverId: string; protocolId: string; info: XCoreInfo }) {
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  if (!can('panel:admin')) return null;

  return (
    <div className={styles.settings}>
      <div>
        <Btn variant="ghost" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen((value) => !value)}>
          {open ? 'Скрыть настройки' : 'Настройки подписки'}
        </Btn>
      </div>
      <div id={panelId}>
        {open ? <SettingsForm serverId={serverId} protocolId={protocolId} info={info} /> : null}
      </div>
    </div>
  );
}

function SettingsForm({ serverId, protocolId, info }: { serverId: string; protocolId: string; info: XCoreInfo }) {
  const queryClient = useQueryClient();
  const id = useId();
  const isEntry = info.role === 'entry';
  const [state, setState] = useState<FormState>(() => toState(info));
  const [saved, setSaved] = useState(false);
  const [localError, setLocalError] = useState<{ field: FieldName; message: string } | null>(null);

  const save = useMutation({
    mutationFn: (body: XCoreSettingsBody) => servers.updateXCoreSettings(serverId, protocolId, body),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: qk.serverDetail(serverId) });
      await queryClient.invalidateQueries({ queryKey: qk.servers });
      // Сервер нормализует домены (регистр, повторы): форма показывает то, что он записал.
      const fresh = queryClient.getQueryData<ServerDetail>(qk.serverDetail(serverId))
        ?.protocols.find((protocol) => protocol.id === protocolId)?.xcore;
      if (fresh) setState(toState(fresh));
      setSaved(true);
    },
  });

  const apiError = save.error instanceof ApiError ? save.error : null;
  // Отказ с полем показывается у поля; без поля или с неизвестным полем — общей полосой над кнопкой.
  const apiField = apiError?.field && (FIELDS as string[]).includes(apiError.field) ? (apiError.field as FieldName) : null;
  const errorFor = (field: FieldName): string | null =>
    localError?.field === field ? localError.message : apiField === field ? apiError!.message : null;
  const generalError = save.isError && !apiField
    ? (apiError ? apiError.message : 'Не удалось сохранить настройки.')
    : null;

  function change<K extends FieldName>(field: K, value: FormState[K]) {
    setSaved(false);
    setLocalError(null);
    setState((previous) => ({ ...previous, [field]: value }));
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (save.isPending) return;
    setSaved(false);

    const sortOrder = Number(state.sortOrder);
    if (state.sortOrder.trim() === '' || !Number.isInteger(sortOrder)) {
      setLocalError({ field: 'sortOrder', message: 'Порядок — целое число.' });
      return;
    }
    setLocalError(null);

    save.mutate({
      title: state.title.trim() || null,
      sortOrder,
      subscriptionEnabled: state.subscriptionEnabled,
      // Только изменённое оператором: форма, открытая до чужой правки, не должна молча выключить шифрование.
      ...(state.vlessEncryption !== info.vlessEncryption ? { vlessEncryption: state.vlessEncryption } : {}),
      ...(isEntry
        ? {
            ruDirect: state.ruDirect,
            directDomains: lines(state.directDomains),
            proxyDomains: lines(state.proxyDomains),
            subscriptionHost: state.subscriptionHost.trim() || null,
          }
        : {}),
    });
  }

  const fieldProps = (field: FieldName) => {
    const error = errorFor(field);
    return {
      'aria-invalid': error ? true : undefined,
      'aria-describedby': error ? `${id}-${field}-error` : `${id}-${field}-hint`,
    };
  };
  const fieldError = (field: FieldName) => {
    const error = errorFor(field);
    return error ? <p id={`${id}-${field}-error`} className={styles.fieldError} role="alert">{error}</p> : null;
  };

  return (
    <form className={styles.form} onSubmit={submit} aria-busy={save.isPending}>
      <div className={styles.grid}>
        <div className="field">
          <label htmlFor={`${id}-title`}>Название в приложении</label>
          <input
            id={`${id}-title`} className="input" value={state.title} maxLength={TITLE_MAX_LENGTH}
            disabled={save.isPending} autoComplete="off" {...fieldProps('title')}
            onChange={(event) => change('title', event.target.value)}
          />
          <p id={`${id}-title-hint`} className={styles.hint}>До {TITLE_MAX_LENGTH} символов. Пусто — имя узла.</p>
          {fieldError('title')}
        </div>
        <div className="field">
          <label htmlFor={`${id}-sortOrder`}>Порядок</label>
          <input
            id={`${id}-sortOrder`} className="input" type="number" step={1} value={state.sortOrder}
            disabled={save.isPending} {...fieldProps('sortOrder')}
            onChange={(event) => change('sortOrder', event.target.value)}
          />
          <p id={`${id}-sortOrder-hint`} className={styles.hint}>Меньше — выше в списке подключений.</p>
          {fieldError('sortOrder')}
        </div>
      </div>

      <label className={styles.checkbox}>
        <input
          type="checkbox" checked={state.subscriptionEnabled} disabled={save.isPending}
          onChange={(event) => change('subscriptionEnabled', event.target.checked)}
        />
        В подписке
      </label>

      <label className={styles.checkbox}>
        <input
          type="checkbox" checked={state.vlessEncryption} disabled={save.isPending}
          aria-describedby={`${id}-vlessEncryption-hint`}
          onChange={(event) => change('vlessEncryption', event.target.checked)}
        />
        Шифрование VLESS (mlkem768x25519plus)
      </label>
      <p id={`${id}-vlessEncryption-hint`} className={styles.hint}>
        Включайте только после проверки в Happ: при отсутствии поддержки подключение через этот узел перестанет
        работать у всех. Ключи создаются на узле при сохранении, ссылки подписок обновятся сами, но у устройств
        со старой копией подписки узел не будет работать до её обновления.
      </p>
      {fieldError('vlessEncryption')}

      {isEntry ? (
        <>
          <label className={styles.checkbox}>
            <input
              type="checkbox" checked={state.ruDirect} disabled={save.isPending}
              onChange={(event) => change('ruDirect', event.target.checked)}
            />
            РФ напрямую
          </label>
          <p className={styles.hint}>
            Российские сайты и адреса идут со входа в интернет напрямую, остальное — через выходы.
          </p>

          <div className={styles.grid}>
            <div className="field">
              <label htmlFor={`${id}-directDomains`}>Всегда напрямую</label>
              <textarea
                id={`${id}-directDomains`} className="input" rows={6} value={state.directDomains}
                disabled={save.isPending} spellCheck={false} {...fieldProps('directDomains')}
                onChange={(event) => change('directDomains', event.target.value)}
              />
              <p id={`${id}-directDomains-hint`} className={styles.hint}>
                По одному домену в строке; поддомены входят. Для сервисов, которые общие списки определяют неверно.
              </p>
              {fieldError('directDomains')}
            </div>
            <div className="field">
              <label htmlFor={`${id}-proxyDomains`}>Всегда через VPN</label>
              <textarea
                id={`${id}-proxyDomains`} className="input" rows={6} value={state.proxyDomains}
                disabled={save.isPending} spellCheck={false} {...fieldProps('proxyDomains')}
                onChange={(event) => change('proxyDomains', event.target.value)}
              />
              <p id={`${id}-proxyDomains-hint`} className={styles.hint}>
                По одному домену в строке. Сильнее российских списков и правила «РФ напрямую».
              </p>
              {fieldError('proxyDomains')}
            </div>
          </div>

          <div className="field">
            <label htmlFor={`${id}-subscriptionHost`}>Домен подписки на этом входе</label>
            <input
              id={`${id}-subscriptionHost`} className="input" value={state.subscriptionHost}
              placeholder="sub.example.com" disabled={save.isPending} autoComplete="off" spellCheck={false}
              {...fieldProps('subscriptionHost')}
              onChange={(event) => change('subscriptionHost', event.target.value)}
            />
            <p id={`${id}-subscriptionHost-hint`} className={styles.hint}>
              A-запись должна указывать на IP этого входа. Ссылки подписок будут строиться на этот домен, а вход
              проксирует /sub/ на API панели. Пусто — домен не используется.
            </p>
            {fieldError('subscriptionHost')}
          </div>
        </>
      ) : null}

      {generalError ? <ErrorBanner message={generalError} /> : null}
      {saved ? (
        <p className={styles.success} role="status">Настройки сохранены. Узлы синхронизируются в фоне.</p>
      ) : null}
      <div className={styles.actions}>
        <Btn variant="primary" type="submit" disabled={save.isPending}>
          {save.isPending ? 'Сохраняем…' : 'Сохранить'}
        </Btn>
      </div>
    </form>
  );
}

/**
 * Плечи входа к выходам. Список берётся из последней проверки входа (exitHealth); названия — из списка узлов.
 * Загрузку названий список не ждёт: состояние плеча важнее имени, и до загрузки (или при её сбое)
 * показывается короткий идентификатор узла.
 */
export function XCoreExits({ info }: { info: XCoreInfo }) {
  const list = useQuery({
    queryKey: qk.serverList({ pageSize: 200 }),
    queryFn: () => servers.list({ pageSize: 200 }),
  });
  const names = new Map((list.data?.items ?? []).map((server) => [server.id, server.name]));

  return (
    <div className={styles.exits}>
      <div className={styles.exitsTitle}>Выходы, на которые вход передаёт трафик</div>
      {info.exitHealth.length === 0 ? (
        <p className={styles.hint}>
          Состояние плеч появится после ближайшей проверки узла. Если подходящих выходов нет, вход закрыт.
        </p>
      ) : (
        <ul className={styles.exitList}>
          {info.exitHealth.map((exit) => (
            <li key={exit.serverId} className={styles.exitRow}>
              <span className={styles.exitName}>{names.get(exit.serverId) ?? `узел …${exit.serverId.slice(-6)}`}</span>
              <Tag tone={exit.ok ? 'neutral' : 'accent'}>{exit.ok ? 'плечо открыто' : 'плечо не отвечает'}</Tag>
              <span className={styles.exitMeta}>
                {exit.ok ? '' : `${exit.error ?? 'причина неизвестна'} · `}проверено {formatLogTime(exit.checkedAt)}
              </span>
            </li>
          ))}
        </ul>
      )}
      {list.isError ? (
        <ErrorBanner message="Не удалось загрузить названия выходов." onRetry={() => void list.refetch()} />
      ) : null}
    </div>
  );
}

/**
 * Российские списки входа одной строкой («релиз … от …») и кнопка «Обновить списки сейчас». Предупреждение об
 * ошибке обновления отдельно от ошибки синхронизации: оно не уходит само после очередной синхронизации
 * подписчиков, пока списки не обновятся. Кнопка только публикует событие — результат появится в карточке
 * после того, как worker его выполнит, поэтому данные узла подтягиваются повторно.
 */
export function XCoreRfLists({ serverId, protocolId, info }: { serverId: string; protocolId: string; info: XCoreInfo }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [requested, setRequested] = useState(false);

  const update = useMutation({
    mutationFn: () => servers.updateXCoreRfLists(serverId, protocolId),
    onSuccess: async () => {
      setRequested(true);
      await queryClient.invalidateQueries({ queryKey: qk.serverDetail(serverId) });
    },
  });

  const summary = info.rfListsTag
    ? `Списки РФ: релиз ${info.rfListsTag} от ${formatLogTime(info.rfListsAppliedAt)}, проверено ${formatLogTime(info.rfListsCheckedAt)}`
    : 'Списки РФ: ещё не загружены, вход работает на встроенных списках.';
  const failure = update.error instanceof ApiError ? update.error.message : 'Не удалось запросить обновление списков.';

  return (
    <div className={styles.rfLists}>
      <p className={styles.hint}>{summary}</p>
      {info.geoError ? <ErrorBanner message={`Списки РФ не обновлены: ${info.geoError}`} /> : null}
      {can('panel:admin') ? (
        <div className={styles.actions}>
          <Btn variant="ghost" disabled={update.isPending} onClick={() => update.mutate()}>
            {update.isPending ? 'Запрашиваем…' : 'Обновить списки сейчас'}
          </Btn>
        </div>
      ) : null}
      {update.isError ? <ErrorBanner message={failure} /> : null}
      {requested && !update.isError ? (
        <p className={styles.success} role="status">Обновление запрошено. Результат появится в карточке через минуту-две.</p>
      ) : null}
    </div>
  );
}
