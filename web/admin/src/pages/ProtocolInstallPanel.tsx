import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { jobs, servers, type ProtocolSpecBody } from '@/api/endpoints';
import type { ProtocolKind, ServerDetail } from '@/api/types';
import { qk } from '@/api/queryKeys';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { Dialog } from '@/components/Dialog';
import { ErrorBanner } from '@/components/Misc';
import { ProtocolDisplay } from '@/lib/protocols';
import { InstallChecklist, InstallLog } from './add-server/InstallChecklist';

const kinds: ProtocolKind[] = ['awg3', 'awg2', 'awg', 'wireguard', 'xray'];
const terminal = (status?: string) => status === 'succeeded' || status === 'failed' || status === 'canceled';

export function ProtocolInstallPanel({ server }: { server: ServerDetail }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const jobId = params.get('job');
  const [open, setOpen] = useState(false);
  const available = kinds.filter((kind) => !server.protocols.some((p) => p.kind === kind));
  const [kind, setKind] = useState<ProtocolKind>('awg3');
  const [port, setPort] = useState('');
  const [subnet, setSubnet] = useState('');
  const [siteName, setSiteName] = useState('www.googletagmanager.com');

  const job = useQuery({
    queryKey: ['job', jobId], queryFn: () => jobs.get(jobId!), enabled: Boolean(jobId),
    refetchInterval: (query) => terminal(query.state.data?.status) ? false : 2000,
  });
  const log = useQuery({
    queryKey: ['protocol-job-log', jobId, job.data?.logSeq],
    queryFn: () => jobs.log(jobId!, Math.max(0, (job.data?.logSeq ?? 0) - 200)),
    enabled: Boolean(jobId),
  });
  useEffect(() => {
    if (!terminal(job.data?.status)) return;
    void queryClient.invalidateQueries({ queryKey: qk.serverDetail(server.id) });
    void queryClient.invalidateQueries({ queryKey: qk.servers });
  }, [job.data?.status, server.id, queryClient]);

  const install = useMutation({
    mutationFn: () => {
      const body: ProtocolSpecBody = { kind };
      if (port.trim()) body.port = port.trim();
      if (kind === 'xray') body.siteName = siteName.trim();
      else if (subnet.trim()) { body.subnetAddress = subnet.trim(); body.subnetCidr = '24'; }
      return servers.addProtocol(server.id, body);
    },
    onSuccess: (accepted) => {
      setOpen(false);
      setParams((previous) => { previous.set('job', accepted.jobId); return previous; });
    },
  });
  const busy = Boolean(jobId && !terminal(job.data?.status));
  return <>
    {can('panel:admin') && available.length > 0 && <Btn variant="secondary" disabled={busy} onClick={() => {
      setKind(available[0]!); setPort(''); setSubnet(''); install.reset(); setOpen(true);
    }}>Добавить / обновить протокол</Btn>}
    {jobId && <div aria-live="polite">
      {job.isPending && <p>Загрузка установки…</p>}
      {job.isError && <ErrorBanner message="Не удалось загрузить установку." onRetry={() => void job.refetch()} />}
      {job.data && <>
        <p>{job.data.status === 'succeeded' ? 'Протокол установлен. Существующие ключи сохранены.' :
          job.data.status === 'failed' || job.data.status === 'canceled' ? 'Установка не завершена. Прежние протоколы сохранены.' : 'Установка нового протокола…'}</p>
        <InstallChecklist job={job.data} />
        {job.data.error && <ErrorBanner message={job.data.error} />}
        <InstallLog lines={log.data?.entries.map((entry) => entry.text) ?? []} />
      </>}
    </div>}
    {open && <Dialog title="Установить протокол рядом с существующими" onClose={() => setOpen(false)} closeDisabled={install.isPending}
      actions={<><Btn variant="ghost" disabled={install.isPending} onClick={() => setOpen(false)}>Отмена</Btn>
        <Btn disabled={install.isPending || !available.includes(kind)} onClick={() => install.mutate()}>
          {install.isPending ? 'Запускаю…' : 'Установить'}
        </Btn></>}>
      <p>Новая версия получит отдельный контейнер, порт и подсеть. Старые протоколы и ключи продолжат работать.</p>
      <div className="field"><label htmlFor="new-protocol">Протокол</label>
        <select className="input" id="new-protocol" value={kind} disabled={install.isPending} onChange={(event) => setKind(event.target.value as ProtocolKind)}>
          {available.map((value) => <option key={value} value={value}>{ProtocolDisplay[value]}</option>)}
        </select></div>
      {kind === 'awg3' && <p>AmneziaWG 3.1 из AmneziaVPN 5.0.2.1. Для нового ключа обновите приложение AmneziaVPN.</p>}
      <div className="field"><label htmlFor="new-port">Порт (пусто — выбрать автоматически)</label>
        <input className="input" id="new-port" type="number" min="1" max="65535" value={port} disabled={install.isPending} onChange={(event) => setPort(event.target.value)} /></div>
      {kind !== 'xray' ? <div className="field"><label htmlFor="new-subnet">Подсеть /24 (пусто — выбрать свободную)</label>
        <input className="input" id="new-subnet" placeholder="10.8.3.0" value={subnet} disabled={install.isPending} onChange={(event) => setSubnet(event.target.value)} /></div>
        : <div className="field"><label htmlFor="new-sni">SNI</label><input className="input" id="new-sni" value={siteName} disabled={install.isPending} onChange={(event) => setSiteName(event.target.value)} /></div>}
      {install.isError && <ErrorBanner message={install.error instanceof ApiError ? install.error.message : 'Не удалось запустить установку.'} />}
    </Dialog>}
  </>;
}
