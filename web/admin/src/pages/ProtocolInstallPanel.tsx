import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { jobs, servers, type ProtocolSpecBody } from '@/api/endpoints';
import type { ProtocolKind, ServerDetail, XCoreRole } from '@/api/types';
import { qk } from '@/api/queryKeys';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { Dialog } from '@/components/Dialog';
import { ErrorBanner } from '@/components/Misc';
import { XCoreRoleField } from '@/components/XCoreRoleField';
import { ProtocolDisplay, XCORE_INSTALL_LABEL } from '@/lib/protocols';
import { InstallChecklist, InstallLog } from './add-server/InstallChecklist';

const kinds: ProtocolKind[] = ['awg3', 'awg2', 'awg', 'wireguard', 'xray', 'xcore'];
const terminal = (status?: string) => status === 'succeeded' || status === 'failed' || status === 'canceled';

export function ProtocolInstallPanel({ server }: { server: ServerDetail }) {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const jobId = params.get('job');
  const [open, setOpen] = useState(false);
  const available = kinds.filter((kind) => !server.protocols.some((p) => p.kind === kind));
  const [kind, setKind] = useState<ProtocolKind>('awg3');
  const [port, setPort] = useState('');
  const [subnet, setSubnet] = useState('');
  const [siteName, setSiteName] = useState('www.googletagmanager.com');
  const [domain, setDomain] = useState('');
  const [role, setRole] = useState<XCoreRole>('exit');

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
    if (job.data?.kind === 'delete_server' && job.data.status === 'succeeded') {
      queryClient.removeQueries({ queryKey: qk.serverDetail(server.id) });
      navigate('/servers', { replace: true });
    } else {
      void queryClient.invalidateQueries({ queryKey: qk.serverDetail(server.id) });
    }
    void queryClient.invalidateQueries({ queryKey: qk.servers });
    void queryClient.invalidateQueries({ queryKey: qk.serverKeys(server.id) });
    void queryClient.invalidateQueries({ queryKey: qk.keys });
    void queryClient.invalidateQueries({ queryKey: qk.users });
    void queryClient.invalidateQueries({ queryKey: qk.dashboard });
  }, [job.data?.status, job.data?.kind, server.id, queryClient, navigate]);

  const install = useMutation({
    mutationFn: () => {
      const body: ProtocolSpecBody = { kind };
      // xcore всегда на 443 и без подсети: порт и подсеть сервер задаёт сам.
      if (kind === 'xcore') {
        body.domain = domain.trim();
        body.role = role;
        return servers.addProtocol(server.id, body);
      }
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
      setKind(available[0]!); setPort(''); setSubnet(''); setDomain(''); setRole('exit'); install.reset(); setOpen(true);
    }}>Добавить / обновить протокол</Btn>}
    {jobId && <div aria-live="polite">
      {job.isPending && <p>Загрузка операции…</p>}
      {job.isError && <ErrorBanner message="Не удалось загрузить операцию." onRetry={() => void job.refetch()} />}
      {job.data && <>
        <p>{job.data.kind === 'cleanup_server' || job.data.kind === 'delete_server' ?
          job.data.status === 'succeeded' ? (job.data.kind === 'cleanup_server' ? 'VPN очищен. Можно установить протоколы заново.' : 'Запись узла удалена.') :
          terminal(job.data.status) ? 'Операция не завершена. Проверьте состояние узла; часть контейнеров могла быть удалена.' : 'Выполняется операция над узлом…' :
          job.data.status === 'succeeded' ? 'Протокол установлен. Существующие ключи сохранены.' :
          job.data.status === 'failed' || job.data.status === 'canceled' ? 'Установка не завершена. Прежние протоколы сохранены.' : 'Установка нового протокола…'}</p>
        <InstallChecklist job={job.data} />
        {job.data.error && <ErrorBanner message={job.data.error} />}
        <InstallLog lines={log.data?.entries.map((entry) => entry.text) ?? []} />
      </>}
    </div>}
    {open && <Dialog title="Установить протокол рядом с существующими" onClose={() => setOpen(false)} closeDisabled={install.isPending}
      actions={<><Btn variant="ghost" disabled={install.isPending} onClick={() => setOpen(false)}>Отмена</Btn>
        <Btn disabled={install.isPending || !available.includes(kind) || (kind === 'xcore' && !domain.trim())} onClick={() => install.mutate()}>
          {install.isPending ? 'Запускаю…' : 'Установить'}
        </Btn></>}>
      <p>{kind === 'xcore'
        ? 'Отдельный контейнер Xray для подписок Happ. Старые протоколы и ключи продолжат работать.'
        : 'Новая версия получит отдельный контейнер, порт и подсеть. Старые протоколы и ключи продолжат работать.'}</p>
      <div className="field"><label htmlFor="new-protocol">Протокол</label>
        <select className="input" id="new-protocol" value={kind} disabled={install.isPending} onChange={(event) => setKind(event.target.value as ProtocolKind)}>
          {available.map((value) => <option key={value} value={value}>{value === 'xcore' ? XCORE_INSTALL_LABEL : ProtocolDisplay[value]}</option>)}
        </select></div>
      {kind === 'awg3' && <p>AmneziaWG 3.1 из AmneziaVPN 5.0.2.1. Для нового ключа обновите приложение AmneziaVPN.</p>}
      {kind === 'xcore' ? <>
        <XCoreRoleField name="new-role" value={role} disabled={install.isPending} onChange={setRole} />
        <div className="field"><label htmlFor="new-domain">Домен</label>
        <input className="input" id="new-domain" placeholder="node1.example.com" value={domain} disabled={install.isPending} onChange={(event) => setDomain(event.target.value)} autoComplete="off" />
        <p>A-запись домена должна указывать на IP узла; порты 80 и 443 должны быть свободны.</p></div></> : <>
      <div className="field"><label htmlFor="new-port">Порт (пусто — выбрать автоматически)</label>
        <input className="input" id="new-port" type="number" min="1" max="65535" value={port} disabled={install.isPending} onChange={(event) => setPort(event.target.value)} /></div>
      {kind !== 'xray' ? <div className="field"><label htmlFor="new-subnet">Подсеть /24 (пусто — выбрать свободную)</label>
        <input className="input" id="new-subnet" placeholder="10.8.3.0" value={subnet} disabled={install.isPending} onChange={(event) => setSubnet(event.target.value)} /></div>
        : <div className="field"><label htmlFor="new-sni">SNI</label><input className="input" id="new-sni" value={siteName} disabled={install.isPending} onChange={(event) => setSiteName(event.target.value)} /></div>}
      </>}
      {install.isError && <ErrorBanner message={install.error instanceof ApiError ? install.error.message : 'Не удалось запустить установку.'} />}
    </Dialog>}
  </>;
}
