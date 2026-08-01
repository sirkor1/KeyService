import { useEffect, useReducer, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { jobs as jobsApi, servers as serversApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { ConnectionTest } from '@/api/types';
import { Btn } from '@/components/Btn';
import { ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { useToast } from '@/components/Toast';
import { InstallChecklist, InstallLog } from './InstallChecklist';
import { Stepper } from './Stepper';
import { StepAccess, StepBasics, StepProtocols } from './Steps';
import { draftReducer, initialDraft, portsToCheck, stepBlocker, toProtocolSpecs } from './draft';
import styles from './AddServerPage.module.css';

/** Как часто спрашиваем состояние задачи, пока она не завершилась. */
const POLL_MS = 1500;

export function AddServerPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { show } = useToast();

  const jobId = params.get('job');
  const [draft, dispatch] = useReducer(draftReducer, initialDraft);
  const [maxReached, setMaxReached] = useState(1);
  const [test, setTest] = useState<ConnectionTest | null>(null);
  const [logLines, setLogLines] = useState<string[]>([]);

  const logSeq = useRef(0);
  const currentStep = jobId ? 4 : draft.step;
  const connectionFingerprint = [
    draft.host,
    draft.sshPort,
    draft.sshUser,
    draft.authType,
    draft.sshPassword,
    draft.sshPrivateKey,
    draft.sshKeyPassphrase,
    ...draft.protocols.flatMap((protocol) => [protocol.enabled ? 'enabled' : 'disabled', protocol.port]),
  ].join('\u0000');

  // Результат SSH-проверки действителен только для точного набора реквизитов
  // и проверяемых портов. После любой правки его нельзя оставлять на экране.
  useEffect(() => {
    setTest(null);
  }, [connectionFingerprint]);

  // Задача опрашивается, пока не придёт терминальный статус. URL с ?job=
  // делает состояние адресуемым: перезагрузка страницы возвращает к прогрессу.
  const job = useQuery({
    queryKey: ['job', jobId],
    queryFn: () => jobsApi.get(jobId!),
    enabled: Boolean(jobId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'succeeded' || status === 'failed' || status === 'canceled' ? false : POLL_MS;
    },
  });

  // Лог дочитывается порциями по seq, а не перезагружается целиком:
  // сборка образа выдаёт тысячи строк.
  useEffect(() => {
    if (!jobId) return;

    let stopped = false;

    async function pull() {
      try {
        const chunk = await jobsApi.log(jobId!, logSeq.current);
        if (stopped || chunk.entries.length === 0) return;

        logSeq.current = chunk.nextSeq;
        setLogLines((prev) => [...prev, ...chunk.entries.map((e) => e.text)]);
      } catch {
        // Хвост лога не критичен: чеклист показывает состояние и без него.
      }
    }

    void pull();
    const timer = setInterval(() => void pull(), POLL_MS);

    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [jobId, job.data?.logSeq]);

  useEffect(() => {
    if (job.data?.status !== 'succeeded') return;

    show('Узел добавлен и готов к выдаче ключей');
    void queryClient.invalidateQueries({ queryKey: qk.servers });
    void queryClient.invalidateQueries({ queryKey: qk.dashboard });
  }, [job.data?.status, queryClient, show]);

  const connectionTest = useMutation({
    mutationFn: () =>
      serversApi.testConnection({
        host: draft.host.trim(),
        sshPort: Number(draft.sshPort) || 22,
        sshUser: draft.sshUser.trim(),
        ...(draft.authType === 'password'
          ? { sshPassword: draft.sshPassword }
          : {
              sshPrivateKey: draft.sshPrivateKey,
              ...(draft.sshKeyPassphrase ? { sshKeyPassphrase: draft.sshKeyPassphrase } : {}),
            }),
        ports: portsToCheck(draft),
      }),
    onSuccess: setTest,
    onMutate: () => setTest(null),
  });

  const install = useMutation({
    mutationFn: () =>
      serversApi.install({
        host: draft.host.trim(),
        name: draft.name.trim(),
        ...(draft.geo.trim() ? { geo: draft.geo.trim() } : {}),
        ...(draft.provider.trim() ? { provider: draft.provider.trim() } : {}),
        ...(draft.note.trim() ? { note: draft.note.trim() } : {}),
        ...(draft.keyLimit.trim() ? { keyLimit: Number(draft.keyLimit) } : {}),
        sshPort: Number(draft.sshPort) || 22,
        sshUser: draft.sshUser.trim(),
        ...(draft.authType === 'password'
          ? { sshPassword: draft.sshPassword }
          : {
              sshPrivateKey: draft.sshPrivateKey,
              ...(draft.sshKeyPassphrase ? { sshKeyPassphrase: draft.sshKeyPassphrase } : {}),
            }),
        protocols: toProtocolSpecs(draft),
      }),
    onSuccess: (accepted) => {
      logSeq.current = 0;
      setLogLines([]);
      setParams({ job: accepted.jobId }, { replace: true });
    },
  });

  const cancel = useMutation({
    mutationFn: (id: string) => jobsApi.cancel(id),
    onSuccess: () => void job.refetch(),
  });

  function goTo(step: number) {
    dispatch({ type: 'step', step });
    setMaxReached((prev) => Math.max(prev, step));
  }

  const blocker = stepBlocker(draft);
  const running = job.data && !['succeeded', 'failed', 'canceled'].includes(job.data.status);

  return (
    <>
      <PageHeader
        kicker="Новый узел"
        title="Добавление сервера"
        back={{ to: '/servers', label: 'Все серверы' }}
        actions={
          !jobId ? (
            <Btn variant="secondary" disabled={install.isPending || connectionTest.isPending} onClick={() => navigate('/servers')}>
              Отменить
            </Btn>
          ) : null
        }
      />

      <Stepper current={currentStep} maxReached={jobId ? 4 : maxReached} onGoTo={goTo} disabled={connectionTest.isPending || install.isPending || Boolean(jobId)} />

      <div className={styles.columns}>
        <div className={styles.main}>
          {install.isError ? (
            <ErrorBanner
              message={
                install.error instanceof ApiError
                  ? install.error.message
                  : 'Не удалось запустить установку.'
              }
            />
          ) : null}
          {connectionTest.isError ? (
            <ErrorBanner
              message={connectionTest.error instanceof ApiError ? connectionTest.error.message : 'Не удалось проверить SSH-подключение.'}
              onRetry={() => connectionTest.mutate()}
            />
          ) : null}
          {cancel.isError ? <ErrorBanner message="Не удалось запросить отмену установки." onRetry={() => jobId && cancel.mutate(jobId)} /> : null}

          {currentStep === 1 && <StepBasics draft={draft} dispatch={dispatch} />}
          {currentStep === 2 && (
            <StepAccess
              draft={draft}
              dispatch={dispatch}
              test={test}
              testing={connectionTest.isPending}
              onTest={() => connectionTest.mutate()}
            />
          )}
          {currentStep === 3 && <StepProtocols draft={draft} dispatch={dispatch} />}

          {currentStep === 4 && (
            jobId && job.isPending ? <Spinner label="Загружаем состояние установки…" /> : jobId && job.isError ? <ErrorBanner message="Не удалось загрузить состояние установки." onRetry={() => void job.refetch()} /> : <StepInstall
              jobId={jobId}
              job={job.data ?? null}
              logLines={logLines}
              installing={install.isPending}
              cancelling={cancel.isPending}
              onInstall={() => install.mutate()}
              onCancel={() => jobId && cancel.mutate(jobId)}
              onRetry={() => {
                setParams({}, { replace: true });
                setLogLines([]);
                logSeq.current = 0;
                goTo(1);
              }}
              onDone={() => navigate(`/servers/${job.data?.serverId}`)}
            />
          )}

          {blocker && currentStep < 4 ? <p className={styles.blocker}>{blocker}</p> : null}

          {currentStep < 4 ? (
            <div className={styles.actions}>
              {currentStep > 1 ? (
                <Btn variant="secondary" disabled={connectionTest.isPending} onClick={() => goTo(currentStep - 1)}>
                  Назад
                </Btn>
              ) : null}

              <Btn variant="primary" disabled={connectionTest.isPending || Boolean(blocker)} onClick={() => goTo(currentStep + 1)}>
                {currentStep === 1
                  ? 'Далее — доступ'
                  : currentStep === 2
                    ? 'Далее — протоколы'
                    : 'Далее — установка'}
              </Btn>
            </div>
          ) : null}
        </div>

        <aside className={styles.aside}>
          <h6>Что произойдёт</h6>
          <ol className={styles.list}>
            <li>Проверка SSH-доступа и отпечатка хоста</li>
            <li>Установка Docker, если он отсутствует</li>
            <li>Развёртывание контейнеров выбранных протоколов</li>
            <li>Генерация серверных ключей и правил файрвола</li>
            <li>Первая проверка соединения из панели</li>
          </ol>

          <h6>Требования к узлу</h6>
          <p className={styles.asideText}>
            Ubuntu 22.04 или Debian 12, чистая система, доступ root по SSH, 1 vCPU и 1 ГБ RAM
            минимум. AmneziaWG требует ядро Linux 4.14 или новее.
          </p>

          {/* Единственное место, где акцент занимает целый блок, — так задумано
              дизайн-системой: предупреждение должно быть заметно. */}
          <div className={styles.poster}>
            <div className={styles.posterKicker}>Важно</div>
            <div className={styles.posterText}>
              Установка перезапишет существующие конфигурации Amnezia на этом узле.
            </div>
          </div>

          {running ? (
            <p className={styles.asideText}>
              Установка идёт в фоне. Страницу можно закрыть — прогресс сохранится, ссылка
              с номером задачи работает и после перезагрузки.
            </p>
          ) : null}
        </aside>
      </div>
    </>
  );
}

function StepInstall({
  jobId,
  job,
  logLines,
  installing,
  cancelling,
  onInstall,
  onCancel,
  onRetry,
  onDone,
}: {
  jobId: string | null;
  job: import('@/api/types').Job | null;
  logLines: string[];
  installing: boolean;
  cancelling: boolean;
  onInstall: () => void;
  onCancel: () => void;
  onRetry: () => void;
  onDone: () => void;
}) {
  if (!jobId || !job) {
    return (
      <>
        <h6>Проверка и установка</h6>
        <p className={styles.asideText}>
          Панель подключится по SSH, установит Docker при необходимости и развернёт контейнеры
          выбранных протоколов. Это занимает от трёх до десяти минут.
        </p>
        <div className={styles.actions}>
          <Btn variant="primary" disabled={installing} onClick={onInstall}>
            {installing ? 'Запускаем…' : 'Установить и добавить'}
          </Btn>
        </div>
      </>
    );
  }

  return (
    <section aria-live="polite" aria-busy={installing || cancelling}>
      <h6>Установка</h6>

      <div className={styles.progressRow}>
        <div className={styles.progressTrack}>
          <div className={styles.progressFill} style={{ inlineSize: `${job.progressPercent}%` }} />
        </div>
        <span className={styles.progressValue}>{job.progressPercent}%</span>
      </div>

      <InstallChecklist job={job} />

      {job.error ? <ErrorBanner message={job.error} /> : null}

      <InstallLog lines={logLines} />

      <div className={styles.actions}>
        {job.status === 'succeeded' ? (
          <Btn variant="primary" onClick={onDone}>
            Перейти к узлу
          </Btn>
        ) : job.status === 'failed' || job.status === 'canceled' ? (
          <Btn variant="primary" onClick={onRetry}>
            Начать заново
          </Btn>
        ) : (
          <Btn variant="secondary" disabled={job.cancelRequested || cancelling} onClick={onCancel}>
            {job.cancelRequested || cancelling ? 'Отмена запрошена…' : 'Отменить установку'}
          </Btn>
        )}
      </div>

      {job.cancelRequested && job.status === 'running' ? (
        <p className={styles.blocker}>
          Отмена вступит в силу после текущего шага: прервать идущую сборку образа безопасно нельзя.
        </p>
      ) : null}
    </section>
  );
}
