import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { jobs, servers } from '@/api/endpoints';
import type { ServerDetail } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { Dialog } from '@/components/Dialog';
import { ErrorBanner, SectionTitle } from '@/components/Misc';

export function ServerMaintenancePanel({ server }: { server: ServerDetail }) {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [action, setAction] = useState<'cleanup' | 'delete' | null>(null);
  const [confirmation, setConfirmation] = useState('');
  const [forgetKeys, setForgetKeys] = useState(false);
  const jobId = params.get('job');
  const job = useQuery({ queryKey: ['job', jobId], queryFn: () => jobs.get(jobId!), enabled: Boolean(jobId) });
  const busy = Boolean(jobId && !['succeeded', 'failed', 'canceled'].includes(job.data?.status ?? ''));
  const operation = useMutation({
    mutationFn: () => action === 'cleanup' ? servers.cleanup(server.id, confirmation) : servers.delete(server.id, confirmation, forgetKeys),
    onSuccess: (accepted) => {
      setAction(null);
      setParams(previous => { previous.set('job', accepted.jobId); return previous; });
    },
  });
  if (!can('panel:admin')) return null;
  const open = (value: 'cleanup' | 'delete') => { setConfirmation(''); setForgetKeys(false); operation.reset(); setAction(value); };
  return <section>
    <SectionTitle>Очистка и удаление узла</SectionTitle>
    <p>Очистка удаляет зарегистрированные VPN-контейнеры и отключает все их ключи, включая подключения, созданные вне панели. Карточка узла и SSH-доступ сохраняются.</p>
    <p>Удаление записи убирает узел и все выданные им ключи из базы без подключения к серверу. Если отозвать ключи невозможно, можно подтвердить удаление без отзыва доступа.</p>
    <Btn variant="secondary" disabled={busy || operation.isPending || server.protocols.length === 0} onClick={() => open('cleanup')}>Очистить VPN на узле</Btn>{' '}
    <Btn variant="ghost" disabled={busy || operation.isPending} onClick={() => open('delete')}>Удалить узел из панели</Btn>
    {action && <Dialog title={action === 'cleanup' ? `Очистить «${server.name}»?` : `Удалить «${server.name}» из панели?`}
      onClose={() => setAction(null)} closeDisabled={operation.isPending}
      actions={<>
        <Btn variant="secondary" disabled={operation.isPending} onClick={() => setAction(null)}>Отмена</Btn>
        <Btn disabled={operation.isPending || confirmation !== server.name} onClick={() => operation.mutate()}>
          {operation.isPending ? 'Запускаем…' : action === 'cleanup' ? 'Удалить VPN-контейнеры и ключи' : 'Удалить запись узла'}
        </Btn>
      </>}>
      <p>{server.host}:{server.ssh.port}</p>
      {action === 'cleanup' ? <>
        <p>Будут удалены контейнеры с их конфигурациями:</p>
        <ul>{server.protocols.map(p => <li key={p.id}>{p.displayName} — {p.containerName}</li>)}</ul>
        <p>Все подключения к ним перестанут работать. Восстановить прежние ключи после очистки нельзя. История выдачи останется в панели со статусом «отозван».</p>
        <p>Другие контейнеры, Docker и система сохранятся. Внешние каталоги и тома автоматически не удаляются.</p>
      </> : <>
        <p>Будут удалены карточка, сохранённый SSH-доступ и все выданные этим узлом ключи из базы, включая отозванные. История выдачи и конфигурации этих ключей будут удалены без возможности восстановления через панель. Журнал операций сохранится.</p>
        <p>Подключение к серверу не требуется. Контейнеры и настройки VPN на сервере останутся без изменений. Если есть неотозванные ключи, подтвердите удаление без отзыва доступа.</p>
        <label><input type="checkbox" checked={forgetKeys} disabled={operation.isPending}
          onChange={event => setForgetKeys(event.target.checked)} /> Удалить запись без отзыва ключей. Я понимаю, что выданные конфигурации могут работать, когда сервер включится.</label>
      </>}
      <div className="field"><label htmlFor="maintenance-confirmation">Введите имя узла: {server.name}</label>
        <input className="input" id="maintenance-confirmation" value={confirmation} autoComplete="off"
          disabled={operation.isPending} onChange={event => setConfirmation(event.target.value)} /></div>
      {operation.isError && <ErrorBanner message={operation.error instanceof ApiError ? operation.error.message : 'Не удалось запустить операцию.'} />}
    </Dialog>}
  </section>;
}
