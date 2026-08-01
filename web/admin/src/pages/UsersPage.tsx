import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { ApiError } from '@/api/client';
import { users as usersApi, type CreatePanelUserBody, type UpdatePanelUserBody } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { UserListItem, UserRole, UserStatus } from '@/api/types';
import { useAuth } from '@/auth/AuthProvider';
import { Btn } from '@/components/Btn';
import { ConfirmDialog, Dialog } from '@/components/Dialog';
import { FilterBar, SearchInput } from '@/components/Filters';
import { ErrorBanner, Stacked } from '@/components/Misc';
import { PageHeader } from '@/components/PageHeader';
import { Spinner } from '@/components/Spinner';
import { StatusTag } from '@/components/Tag';
import { Table, type Column } from '@/components/Table';
import { useToast } from '@/components/Toast';
import { formatDate, formatNumber } from '@/lib/format';
import { userRole, userStatus } from '@/lib/labels';
import styles from './UsersPage.module.css';

const PANEL_ROLES: Array<Extract<UserRole, 'admin' | 'operator' | 'viewer'>> = [
  'admin',
  'operator',
  'viewer',
];

function canManage(actorRole: UserRole, target: UserListItem, actorId: string): boolean {
  if (target.id === actorId) return true;
  if (actorRole === 'owner') return target.role !== 'owner';
  return actorRole === 'admin' && (target.role === 'operator' || target.role === 'viewer' || target.role === 'client');
}

function allowedRoles(actorRole: UserRole, currentRole?: UserRole): UserRole[] {
  // Свою роль и роли, которые API намеренно не назначает через этот экран,
  // всё равно показываем в disabled select, а не превращаем поле в пустое.
  if (currentRole === 'owner' || currentRole === actorRole) return [currentRole];
  const assignable = PANEL_ROLES.filter((role) => actorRole === 'owner' || role !== 'admin');
  // Client нельзя назначить API, но owner/admin вправе повысить существующего
  // клиента. Оставляем текущую роль в select, чтобы редактирование профиля не
  // повышало его неявно.
  return currentRole === 'client' ? ['client', ...assignable] : assignable;
}

function columns(onEdit: (user: UserListItem) => void): Column<UserListItem>[] {
  return [
    {
      key: 'name', header: 'Пользователь', width: '25%', noEllipsis: true,
      render: (row) => <Stacked primary={row.displayName ?? row.username} secondary={row.username} />,
      title: (row) => row.username,
    },
    {
      key: 'contact', header: 'Контакт', width: '21%',
      render: (row) => row.contact ?? (row.telegramId ? `Telegram ID ${row.telegramId}` : '—'),
      title: (row) => row.contact ?? undefined,
    },
    { key: 'role', header: 'Роль', width: '12%', render: (row) => userRole[row.role] },
    { key: 'keys', header: 'Ключей', width: '9%', render: (row) => <span className="tabular">{formatNumber(row.keysCount)}</span> },
    { key: 'created', header: 'Создан', width: '13%', render: (row) => formatDate(row.createdAt) },
    { key: 'status', header: 'Статус', width: '12%', noEllipsis: true, render: (row) => <StatusTag status={userStatus[row.status]} /> },
    {
      key: 'actions', header: 'Действия', width: '8%', align: 'right', noEllipsis: true,
      render: (row) => <Btn variant="ghost" onClick={() => onEdit(row)}>Открыть</Btn>,
    },
  ];
}

export function UsersPage() {
  const [params, setParams] = useSearchParams();
  const { user, can } = useAuth();
  const queryClient = useQueryClient();
  const { show } = useToast();
  const [editing, setEditing] = useState<UserListItem | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState<{ user: UserListItem; kind: 'block' | 'unblock' | 'deactivate' } | null>(null);
  const search = params.get('search') ?? '';
  const isAdmin = can('panel:admin');

  const query = useQuery({
    queryKey: qk.userList({ search }), queryFn: () => usersApi.list({ search }), placeholderData: keepPreviousData, enabled: isAdmin,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: qk.users });
    void queryClient.invalidateQueries({ queryKey: qk.dashboard });
  };
  const statusMutation = useMutation({
    mutationFn: async ({ id, kind }: { id: string; kind: 'block' | 'unblock' | 'deactivate' }) => {
      if (kind === 'block') await usersApi.block(id);
      else if (kind === 'unblock') await usersApi.unblock(id);
      else await usersApi.deactivate(id);
    },
    onSuccess: () => { setConfirm(null); invalidate(); show('Статус пользователя обновлён'); },
  });

  if (!isAdmin) return <ErrorBanner message="У вас нет прав на управление пользователями." />;

  return (
    <>
      <PageHeader
        kicker="Клиенты"
        title="Пользователи"
        actions={<Btn variant="primary" onClick={() => setCreating(true)}>Создать пользователя</Btn>}
      />
      <FilterBar shown={query.data?.items.length ?? 0} total={query.data?.total ?? 0}>
        <SearchInput value={search} onChange={(value) => {
          const next = new URLSearchParams(params);
          if (value) next.set('search', value); else next.delete('search');
          setParams(next, { replace: true });
        }} placeholder="Поиск по имени или контакту" />
      </FilterBar>
      {query.isPending ? <Spinner /> : query.isError ? (
        <ErrorBanner message="Не удалось загрузить список пользователей." onRetry={() => void query.refetch()} />
      ) : <Table columns={columns(setEditing)} rows={query.data?.items ?? []} rowKey={(row) => row.id} empty="Пользователей пока нет." />}
      {creating && user ? <UserEditor actor={user} onClose={() => setCreating(false)} onDone={() => { setCreating(false); invalidate(); show('Пользователь создан'); }} /> : null}
      {editing && user ? <UserEditor actor={user} initial={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); invalidate(); show('Профиль пользователя обновлён'); }} onAction={setConfirm} /> : null}
      {confirm ? <ConfirmDialog
        title={confirm.kind === 'deactivate' ? `Деактивировать ${confirm.user.username}?` : `${confirm.kind === 'block' ? 'Заблокировать' : 'Разблокировать'} ${confirm.user.username}?`}
        body={confirm.kind === 'deactivate' ? 'Учётная запись сохранится для истории и связанных ключей, но вход будет запрещён.' : 'Изменение статуса применяется сразу.'}
        confirmLabel={confirm.kind === 'deactivate' ? 'Деактивировать' : confirm.kind === 'block' ? 'Заблокировать' : 'Разблокировать'}
        busy={statusMutation.isPending}
        onConfirm={() => statusMutation.mutate({ id: confirm.user.id, kind: confirm.kind })}
        onCancel={() => setConfirm(null)}
      /> : null}
      {statusMutation.isError ? <ErrorBanner message={mutationError(statusMutation.error, 'Не удалось изменить статус пользователя.')} /> : null}
    </>
  );
}

function UserEditor({ actor, initial, onClose, onDone, onAction }: {
  actor: { id: string; role: UserRole };
  initial?: UserListItem;
  onClose: () => void;
  onDone: () => void;
  onAction?: (value: { user: UserListItem; kind: 'block' | 'unblock' | 'deactivate' }) => void;
}) {
  const isCreate = !initial;
  const manageable = initial ? canManage(actor.role, initial, actor.id) : true;
  const self = initial?.id === actor.id;
  const [username, setUsername] = useState(initial?.username ?? '');
  const [displayName, setDisplayName] = useState(initial?.displayName ?? '');
  const [contact, setContact] = useState(initial?.contact ?? '');
  const [role, setRole] = useState<UserRole>(initial?.role ?? (actor.role === 'owner' ? 'admin' : 'operator'));
  const [status, setStatus] = useState<UserStatus>(initial?.status ?? 'active');
  const [password, setPassword] = useState('');
  const [promotionPassword, setPromotionPassword] = useState('');
  const [resetPassword, setResetPassword] = useState('');
  const promotingClientToPanel = !isCreate && initial?.role === 'client' && role !== 'client';
  const mutation = useMutation({
    mutationFn: () => {
      if (isCreate) {
        const body: CreatePanelUserBody = { username: username.trim(), password, role: role as CreatePanelUserBody['role'], ...(displayName.trim() ? { displayName: displayName.trim() } : {}), ...(contact.trim() ? { contact: contact.trim() } : {}) };
        return usersApi.create(body);
      }
      const body: UpdatePanelUserBody = {
        displayName: displayName.trim() || null,
        contact: contact.trim() || null,
        role,
        status,
        ...(promotingClientToPanel ? { password: promotionPassword } : {}),
      };
      return usersApi.update(initial.id, body);
    },
    onSuccess: onDone,
  });
  const resetMutation = useMutation({
    mutationFn: () => usersApi.resetPassword(initial!.id, resetPassword),
    onSuccess: () => { setResetPassword(''); showToast('Новый пароль сохранён'); },
    onSettled: () => setResetPassword(''),
  });
  const { show: showToast } = useToast();
  const busy = mutation.isPending || resetMutation.isPending;

  useEffect(() => () => { setPassword(''); setPromotionPassword(''); setResetPassword(''); }, []);
  const roles = useMemo(() => allowedRoles(actor.role, initial?.role), [actor.role, initial?.role]);
  const canEditPrivileges = manageable && !self && initial?.role !== 'owner';

  function submit(event: FormEvent) { event.preventDefault(); mutation.mutate(); }

  return <Dialog title={isCreate ? 'Новый пользователь панели' : `Пользователь: ${initial.username}`} onClose={onClose} closeDisabled={busy} actions={<>
    <Btn variant="secondary" onClick={onClose} disabled={busy}>Закрыть</Btn>
    {manageable ? <Btn variant="primary" onClick={() => mutation.mutate()} disabled={mutation.isPending || (isCreate && (!username.trim() || password.length < 12)) || (promotingClientToPanel && promotionPassword.length < 12)}>{mutation.isPending ? 'Сохраняем…' : isCreate ? 'Создать' : 'Сохранить'}</Btn> : null}
  </>}>
    <form className={styles.dialogForm} onSubmit={submit} aria-busy={busy}>
      {!manageable ? <ErrorBanner message="Эта учётная запись недоступна для изменения вашей ролью." /> : null}
      <div className="field"><label htmlFor="panel-username">Логин</label><input id="panel-username" className="input" value={username} data-dialog-initial-focus={isCreate || undefined} disabled={!isCreate || busy} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></div>
      <div className="field"><label htmlFor="panel-name">Отображаемое имя</label><input id="panel-name" className="input" value={displayName} data-dialog-initial-focus={!isCreate && manageable || undefined} disabled={!manageable || busy} onChange={(event) => setDisplayName(event.target.value)} /></div>
      <div className="field"><label htmlFor="panel-contact">Контакт</label><input id="panel-contact" className="input" value={contact} disabled={!manageable || busy} onChange={(event) => setContact(event.target.value)} /></div>
      <div className="field"><label htmlFor="panel-role">Роль</label><select id="panel-role" className="input" value={role} disabled={busy || (!isCreate && !canEditPrivileges)} onChange={(event) => setRole(event.target.value as UserRole)}>{roles.map((value) => <option key={value} value={value}>{userRole[value]}</option>)}</select></div>
      {!isCreate ? <div className="field"><label htmlFor="panel-status">Статус</label><select id="panel-status" className="input" value={status} disabled={busy || !canEditPrivileges} onChange={(event) => setStatus(event.target.value as UserStatus)}>{Object.entries(userStatus).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}</select>{self ? <p className={styles.hint}>Свой статус и роль нельзя менять через управление пользователями.</p> : null}</div> : null}
      {promotingClientToPanel ? <div className="field"><label htmlFor="panel-promotion-password">Пароль для входа в панель</label><input id="panel-promotion-password" className="input" type="password" value={promotionPassword} disabled={busy} onChange={(event) => setPromotionPassword(event.target.value)} autoComplete="new-password" /><p className={styles.hint}>Обязателен при повышении роли. От 12 до 128 символов; пароль не будет показан или сохранён в интерфейсе.</p></div> : null}
      {isCreate ? <div className="field"><label htmlFor="panel-password">Пароль</label><input id="panel-password" className="input" type="password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /><p className={styles.hint}>От 12 до 128 символов. После создания пароль не сохраняется в интерфейсе.</p></div> : null}
      {!isCreate && manageable && !promotingClientToPanel ? <section className={styles.password}><div className="field"><label htmlFor="panel-reset-password">Новый пароль</label><input id="panel-reset-password" className="input" type="password" value={resetPassword} disabled={busy} onChange={(event) => setResetPassword(event.target.value)} autoComplete="new-password" /></div><Btn variant="secondary" onClick={() => resetMutation.mutate()} disabled={busy || resetPassword.length < 12}>{resetMutation.isPending ? 'Сбрасываем…' : 'Сбросить пароль'}</Btn></section> : null}
      {mutation.isError ? <ErrorBanner message={mutationError(mutation.error, 'Не удалось сохранить пользователя.')} /> : null}
      {resetMutation.isError ? <ErrorBanner message={mutationError(resetMutation.error, 'Не удалось сменить пароль.')} /> : null}
      {!isCreate && manageable && !self && initial.role !== 'owner' && onAction ? <div className={styles.operations}>
        {initial.status === 'blocked' ? <Btn variant="secondary" disabled={busy} onClick={() => onAction({ user: initial, kind: 'unblock' })}>Разблокировать</Btn> : <Btn variant="secondary" disabled={busy} onClick={() => onAction({ user: initial, kind: 'block' })}>Заблокировать</Btn>}
        <Btn variant="ghost" disabled={busy} onClick={() => onAction({ user: initial, kind: 'deactivate' })}>Деактивировать</Btn>
      </div> : null}
    </form>
  </Dialog>;
}

function mutationError(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}
