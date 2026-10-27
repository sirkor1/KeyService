import { useReducer, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { servers, type ServerDiscovery } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import { Btn, BtnLink } from '@/components/Btn';
import { ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { useToast } from '@/components/Toast';
import { StepAccess, StepBasics } from './Steps';
import { draftReducer, initialDraft, stepBlocker, type DraftAction } from './draft';
import styles from './AddServerPage.module.css';

export function ImportServerPage() {
  const [draft, dispatch] = useReducer(draftReducer, initialDraft);
  const [preview, setPreview] = useState<ServerDiscovery | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const navigate = useNavigate();
  const queries = useQueryClient();
  const { show } = useToast();
  const connection = () => ({
    host: draft.host.trim(), sshPort: Number(draft.sshPort), sshUser: draft.sshUser.trim(),
    ...(draft.authType === 'password' ? { sshPassword: draft.sshPassword }
      : { sshPrivateKey: draft.sshPrivateKey, sshKeyPassphrase: draft.sshKeyPassphrase }),
  });
  const discovery = useMutation({
    mutationFn: () => servers.discover(connection()),
    onMutate: () => { setPreview(null); setSelected([]); registration.reset(); },
    onSuccess: (result) => {
      setPreview(result);
      setSelected(result.protocols.filter(p => p.canImport).map(p => p.containerName));
    },
  });
  const registration = useMutation({
    mutationFn: () => servers.importExisting({
      ...connection(), name: draft.name.trim(), geo: draft.geo.trim() || undefined,
      provider: draft.provider.trim() || undefined, note: draft.note.trim() || undefined,
      keyLimit: draft.keyLimit.trim() ? Number(draft.keyLimit) : undefined,
      revision: preview!.revision, containers: selected,
    }),
    onSuccess: (server) => {
      void queries.invalidateQueries({ queryKey: qk.servers });
      void queries.invalidateQueries({ queryKey: qk.dashboard });
      show('Существующий сервер подключён');
      navigate(`/servers/${server.id}`);
    },
  });
  const busy = discovery.isPending || registration.isPending;
  const change = (action: DraftAction) => {
    dispatch(action);
    setPreview(null);
    setSelected([]);
    discovery.reset();
    registration.reset();
  };
  const port = Number(draft.sshPort);
  const limit = Number(draft.keyLimit);
  const blocker = stepBlocker({ ...draft, step: 1 }) || stepBlocker({ ...draft, step: 2 }) ||
    (!Number.isInteger(port) || port < 1 || port > 65535 ? 'SSH-порт должен быть числом от 1 до 65535.' : null) ||
    (draft.keyLimit.trim() && (!Number.isInteger(limit) || limit < 1) ? 'Лимит ключей должен быть положительным целым числом.' : null);
  const error = registration.error ?? discovery.error;
  return (
    <>
      <PageHeader kicker="Новый узел" title="Подключить существующий сервер"
        back={{ to: '/servers', label: 'Все серверы' }} />
      <div className={styles.columns} aria-busy={busy}>
        <div className={styles.main}>
          <fieldset className={styles.importFields} disabled={busy}>
            <legend className={styles.hint}>1. Укажите сервер и SSH-доступ</legend>
            <StepBasics draft={draft} dispatch={change} />
            <StepAccess draft={draft} dispatch={change} test={null} testing={busy}
              description="Панель прочитает настройки работающих VPN-контейнеров. SSH-пароль и приватный ключ сохраняются в зашифрованном виде."
              testLabel="Найти установленные протоколы" canTest={!blocker}
              onTest={() => discovery.mutate()} />
          </fieldset>
          {blocker && <p className={styles.hint}>{blocker}</p>}
          {error && <ErrorBanner message={error instanceof ApiError ? error.message : 'Не удалось проверить или подключить сервер. Повторите поиск протоколов.'} />}
          {discovery.isPending && <p role="status">Читаем конфигурацию сервера…</p>}
          {preview && (
            <section aria-label="Найденные протоколы">
              <h6>2. Выберите протоколы</h6>
              <p className={styles.hint} role="status">Готово к подключению: {preview.protocols.filter(p => p.canImport).length}.</p>
              {preview.warnings.map(warning => <p key={warning} className={styles.testWarn}>{warning}</p>)}
              {preview.protocols.length === 0 ? <p role="status">Поддерживаемые контейнеры не найдены. Проверьте адрес сервера и установленные протоколы.</p> : (
                <div className={styles.protocolList}>
                  {preview.protocols.map(protocol => (
                    <div key={protocol.containerName} className={styles.protocolRow}>
                      <label className={styles.protocolHead}>
                        <input type="checkbox" checked={selected.includes(protocol.containerName)}
                          disabled={busy || !protocol.canImport}
                          onChange={event => setSelected(current => event.target.checked
                            ? [...current, protocol.containerName] : current.filter(c => c !== protocol.containerName))} />
                        <span className={styles.protocolName}>{protocol.displayName}</span>
                      </label>
                      <p className={styles.hint}>{protocol.containerName}</p>
                      {protocol.canImport ? <p className={styles.hint}>
                        UDP {protocol.port} · Подсеть {protocol.subnet} · Существующих подключений: {protocol.peerCount}
                      </p> : <p className={styles.testWarn}>{protocol.error}</p>}
                    </div>
                  ))}
                </div>
              )}
              <p className={styles.hint}>Существующие подключения продолжат работать. Их владельцы и история выдачи не восстанавливаются. Панель будет учитывать старые адреса при выдаче новых ключей.</p>
              <Btn variant="primary" disabled={busy || selected.length === 0 || Boolean(blocker)} onClick={() => registration.mutate()}>
                {registration.isPending ? 'Подключаем…' : `Подключить выбранные (${selected.length})`}
              </Btn>
            </section>
          )}
        </div>
        <aside className={styles.aside}>
          <h6>Подключение без переустановки</h6>
          <p className={styles.asideText}>Используйте этот режим, если VPN уже настроен или база панели была потеряна. Контейнеры, конфигурации и ключи на сервере сохраняются.</p>
          <h6>Поддерживаемые протоколы</h6>
          <p className={styles.asideText}>WireGuard, AmneziaWG 1.0, 2.0 и 3.1 в стандартных контейнерах Amnezia. Остановленные контейнеры и конфигурации, которые не удалось проверить, подключить нельзя.</p>
          <p className={styles.asideText}>Перед подключением сохраните резервную копию конфигураций VPN-узла. Используйте тот же адрес и SSH-порт, под которыми сервер будет доступен панели и клиентам.</p>
          <BtnLink to="/servers/add" variant="secondary">Установить VPN на новый сервер</BtnLink>
        </aside>
      </div>
    </>
  );
}
