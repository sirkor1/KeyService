import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { passcodes as passcodesApi } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { PassCode } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ConfirmDialog } from '@/components/Dialog';
import { EmptyState, ErrorBanner } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { useToast } from '@/components/Toast';
import { formatDate } from '@/lib/format';
import styles from './PassCodesPage.module.css';

function passCodeStatus(code: PassCode) {
  if (code.isRevoked) return { label: 'отозван', tone: 'accent' as const };
  if (code.isUsed) return { label: 'использован', tone: 'outline' as const };
  return { label: 'активен', tone: 'neutral' as const };
}

export function PassCodesPage() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const { show } = useToast();
  const [code, setCode] = useState('');
  const [pendingRevoke, setPendingRevoke] = useState<PassCode | null>(null);
  const canWrite = can('panel:write');
  const query = useQuery({ queryKey: qk.passcodes, queryFn: passcodesApi.list, enabled: canWrite });
  const create = useMutation({
    mutationFn: () => passcodesApi.create(code.trim()),
    onSuccess: (created) => { setCode(''); void queryClient.invalidateQueries({ queryKey: qk.passcodes }); show(`Код ${created.code} создан`); },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => passcodesApi.revoke(id),
    onSuccess: () => { setPendingRevoke(null); void queryClient.invalidateQueries({ queryKey: qk.passcodes }); show('Пригласительный код отозван'); },
  });

  function submit(event: FormEvent) { event.preventDefault(); create.mutate(); }
  async function copy(value: string) {
    try { await navigator.clipboard.writeText(value); show('Код скопирован'); }
    catch { show('Не удалось скопировать код — скопируйте его вручную.'); }
  }

  if (!canWrite) return <ErrorBanner message="У вас нет прав на управление пригласительными кодами." />;

  return <>
    <PageHeader kicker="Клиенты" title="Пригласительные коды" />
    <form className={styles.create} onSubmit={submit} aria-busy={create.isPending}>
      <div className="field"><label htmlFor="invite-code">Новый код</label><input id="invite-code" className="input" value={code} disabled={create.isPending} onChange={(event) => setCode(event.target.value)} placeholder="Например, TEAM-2026" autoComplete="off" /></div>
      <Btn variant="primary" type="submit" disabled={create.isPending || code.trim().length < 4}>{create.isPending ? 'Создаём…' : 'Создать код'}</Btn>
    </form>
    <p className={styles.hint}>Код используется один раз. Отозвать можно только активный, ещё не использованный код.</p>
    {create.isError ? <ErrorBanner message={errorMessage(create.error, 'Не удалось создать код.')} /> : null}
    {revoke.isError ? <ErrorBanner message={errorMessage(revoke.error, 'Не удалось отозвать код.')} /> : null}
    {query.isPending ? <Spinner /> : query.isError ? <ErrorBanner message="Не удалось загрузить пригласительные коды." onRetry={() => void query.refetch()} /> : query.data?.length ? <div className={styles.list}>
      {query.data.map((item) => <article key={item.id} className={styles.row}>
        <div className={styles.code}><span className="mono">{item.code}</span><span className={styles.created}>создан {formatDate(item.createdAt)}</span></div>
        <StatusTag status={passCodeStatus(item)} />
        <div className={styles.used}>{item.usedAt ? `использован ${formatDate(item.usedAt)}` : item.revokedAt ? `отозван ${formatDate(item.revokedAt)}` : 'ещё не использован'}</div>
        <div className={styles.actions}><Btn variant="ghost" onClick={() => void copy(item.code)}>Копировать</Btn>{!item.isUsed && !item.isRevoked ? <Btn variant="ghost" disabled={revoke.isPending} onClick={() => setPendingRevoke(item)}>Отозвать</Btn> : null}</div>
      </article>)}
    </div> : <EmptyState title="Пригласительных кодов пока нет" hint="Создайте код и передайте его пользователю для самостоятельной регистрации." />}
    {pendingRevoke ? <ConfirmDialog title={`Отозвать код ${pendingRevoke.code}?`} body="После отзыва этот код больше нельзя будет использовать для регистрации. История кода сохранится." confirmLabel="Отозвать" busy={revoke.isPending} onConfirm={() => revoke.mutate(pendingRevoke.id)} onCancel={() => setPendingRevoke(null)} /> : null}
  </>;
}

function errorMessage(error: unknown, fallback: string): string { return error instanceof ApiError ? error.message : fallback; }
