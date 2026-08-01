import type { Dispatch } from 'react';
import type { ConnectionTest, ProtocolKind } from '@/api/types';
import { Btn, cx } from '@/components/Btn';
import { Seg } from '@/components/Filters';
import { ProtocolDisplay } from '@/lib/protocols';
import type { Draft, DraftAction } from './draft';
import styles from './AddServerPage.module.css';

interface StepProps {
  draft: Draft;
  dispatch: Dispatch<DraftAction>;
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
  hint,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
  hint?: string;
  disabled?: boolean;
}) {
  const id = `f-${label.replace(/\s+/g, '-').toLowerCase()}`;

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        type={type}
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint ? <p className={styles.hint}>{hint}</p> : null}
    </div>
  );
}

export function StepBasics({ draft, dispatch }: StepProps) {
  const set = (field: keyof Draft) => (value: string) =>
    dispatch({ type: 'set', field, value });

  return (
    <>
      <h6>Основные параметры</h6>

      <Field label="Имя сервера" value={draft.name} onChange={set('name')}
             placeholder="Например, Amsterdam-03" />
      <Field label="IP-адрес или домен" value={draft.host} onChange={set('host')}
             placeholder="185.20.44.19" />
      <Field label="SSH-порт" value={draft.sshPort} onChange={set('sshPort')} />
      <Field label="Локация" value={draft.geo} onChange={set('geo')}
             placeholder="Нидерланды, Амстердам" />
      <Field label="Провайдер" value={draft.provider} onChange={set('provider')}
             placeholder="Hetzner" />
      <Field label="Лимит ключей на узел" value={draft.keyLimit} onChange={set('keyLimit')}
             placeholder="без ограничения" />

      <div className="field">
        <label htmlFor="note">Заметка</label>
        <textarea
          id="note"
          className="input"
          value={draft.note}
          placeholder="Для чего используется этот узел"
          onChange={(e) => dispatch({ type: 'set', field: 'note', value: e.target.value })}
        />
      </div>
    </>
  );
}

export function StepAccess({
  draft,
  dispatch,
  test,
  testing,
  onTest,
}: StepProps & { test: ConnectionTest | null; testing: boolean; onTest: () => void }) {
  const set = (field: keyof Draft) => (value: string) =>
    dispatch({ type: 'set', field, value });

  return (
    <div aria-busy={testing}>
      <h6>SSH-доступ</h6>

      <p className={styles.hint}>
        Панель подключится по SSH и развернёт контейнеры Amnezia самостоятельно. Пароль и приватный
        ключ шифруются перед сохранением и наружу не отдаются — заменить можно, посмотреть нельзя.
      </p>

      <div className="field">
        <label htmlFor="auth">Способ аутентификации</label>
        <Seg
          name="Способ аутентификации"
          value={draft.authType}
          options={[
            { value: 'password', label: 'Пароль' },
            { value: 'privateKey', label: 'Приватный ключ' },
          ]}
          onChange={(value) => dispatch({ type: 'set', field: 'authType', value })}
          disabled={testing}
        />
      </div>

      <Field label="Пользователь" value={draft.sshUser} onChange={set('sshUser')} disabled={testing} />

      {draft.authType === 'password' ? (
        <Field label="Пароль" type="password" value={draft.sshPassword}
               onChange={set('sshPassword')} disabled={testing} />
      ) : (
        <>
          <div className="field">
            <label htmlFor="pk">Приватный ключ</label>
            <textarea
              id="pk"
              className={cx('input', styles.keyArea)}
              value={draft.sshPrivateKey}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              disabled={testing}
              onChange={(e) =>
                dispatch({ type: 'set', field: 'sshPrivateKey', value: e.target.value })
              }
            />
          </div>
          <Field label="Пароль ключа (если задан)" type="password"
                 value={draft.sshKeyPassphrase} onChange={set('sshKeyPassphrase')} disabled={testing} />
        </>
      )}

      <div className={styles.actions}>
        <Btn variant="secondary" disabled={testing} onClick={onTest}>
          {testing ? 'Проверяем…' : 'Проверить подключение'}
        </Btn>
      </div>

      {test ? <ConnectionResult test={test} /> : null}
    </div>
  );
}

function ConnectionResult({ test }: { test: ConnectionTest }) {
  if (!test.ok) {
    return (
      <div className={styles.testFail} role="alert">
        <strong>Подключиться не удалось.</strong> {test.error}
      </div>
    );
  }

  return (
    <div className={styles.testOk} role="status">
      <div>Подключение установлено.</div>
      {test.kernel ? <div>Ядро: {test.kernel}</div> : null}
      <div>Docker: {test.dockerVersion ?? 'не установлен — будет установлен при развёртывании'}</div>
      <div>
        sudo без пароля:{' '}
        {test.sudoAvailable ? 'доступен' : 'НЕДОСТУПЕН — установка не пройдёт'}
      </div>
      {test.hostFingerprint ? <div>Отпечаток: {test.hostFingerprint}</div> : null}
      {test.busyPorts.length > 0 ? (
        <div className={styles.testWarn}>
          Порты уже заняты: {test.busyPorts.join(', ')}. Выберите другие на следующем шаге.
        </div>
      ) : null}
    </div>
  );
}

const PROTOCOL_NOTE: Record<ProtocolKind, string> = {
  awg2: 'обфусцированный WireGuard, рекомендуется по умолчанию',
  awg: 'предыдущая версия AmneziaWG',
  wireguard: 'быстрый, но легко определяется DPI',
  xray: 'маскировка под TLS-трафик к чужому сайту',
};

export function StepProtocols({ draft, dispatch }: StepProps) {
  return (
    <>
      <h6>Протоколы</h6>

      <div className={styles.protocolList}>
        {draft.protocols.map((protocol) => (
          <div key={protocol.kind} className={styles.protocolRow}>
            <div className={styles.protocolHead}>
              <span className={styles.protocolName}>{ProtocolDisplay[protocol.kind]}</span>
              <span className={styles.protocolNote}>{PROTOCOL_NOTE[protocol.kind]}</span>
              <button
                type="button"
                className={cx(styles.toggle, protocol.enabled && styles.toggleOn)}
                onClick={() => dispatch({ type: 'toggleProtocol', kind: protocol.kind })}
              >
                {protocol.enabled ? 'Включён' : 'Выключен'}
              </button>
            </div>

            {protocol.enabled ? (
              <div className={styles.protocolFields}>
                <div className="field">
                  <label htmlFor={`port-${protocol.kind}`}>Порт</label>
                  <input
                    id={`port-${protocol.kind}`}
                    className="input"
                    value={protocol.port}
                    placeholder={protocol.kind === 'xray' ? '443' : 'случайный'}
                    onChange={(e) =>
                      dispatch({
                        type: 'setProtocol', kind: protocol.kind,
                        field: 'port', value: e.target.value,
                      })
                    }
                  />
                </div>

                {protocol.kind === 'xray' ? (
                  <div className="field">
                    <label htmlFor={`sni-${protocol.kind}`}>Сайт маскировки (SNI)</label>
                    <input
                      id={`sni-${protocol.kind}`}
                      className="input"
                      value={protocol.siteName}
                      onChange={(e) =>
                        dispatch({
                          type: 'setProtocol', kind: protocol.kind,
                          field: 'siteName', value: e.target.value,
                        })
                      }
                    />
                  </div>
                ) : (
                  <>
                    <div className="field">
                      <label htmlFor={`mtu-${protocol.kind}`}>MTU</label>
                      <input
                        id={`mtu-${protocol.kind}`}
                        className="input"
                        value={protocol.mtu}
                        onChange={(e) =>
                          dispatch({
                            type: 'setProtocol', kind: protocol.kind,
                            field: 'mtu', value: e.target.value,
                          })
                        }
                      />
                    </div>
                    <div className="field">
                      <label htmlFor={`subnet-${protocol.kind}`}>Подсеть</label>
                      <input
                        id={`subnet-${protocol.kind}`}
                        className="input"
                        value={protocol.subnetAddress}
                        onChange={(e) =>
                          dispatch({
                            type: 'setProtocol', kind: protocol.kind,
                            field: 'subnetAddress', value: e.target.value,
                          })
                        }
                      />
                    </div>
                  </>
                )}
              </div>
            ) : null}
          </div>
        ))}
      </div>

      <p className={styles.hint}>
        Пустой порт означает случайный из диапазона 30000–50000: постоянный порт по умолчанию сам
        по себе выдаёт Amnezia при сканировании. Пары ключей и pre-shared key генерируются на узле
        при установке.
      </p>
    </>
  );
}
