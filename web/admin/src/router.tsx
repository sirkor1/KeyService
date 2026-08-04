import { createBrowserRouter, Navigate } from 'react-router-dom';
import { RequireAuth } from '@/auth/RequireAuth';
import { AppShell } from '@/layout/AppShell';
import { KeysPage } from '@/pages/KeysPage';
import { LoginPage } from '@/pages/LoginPage';
import { LogsPage } from '@/pages/LogsPage';
import { AddServerPage } from '@/pages/add-server/AddServerPage';
import { IssueKeyPage } from '@/pages/IssueKeyPage';
import { ServerDetailPage } from '@/pages/ServerDetailPage';
import { ServersPage } from '@/pages/ServersPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { UsersPage } from '@/pages/UsersPage';
import { PassCodesPage } from '@/pages/PassCodesPage';
import { NotificationsPage } from '@/pages/NotificationsPage';

export const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to="/servers" replace /> },

      { path: 'servers', element: <ServersPage /> },
      // Статический сегмент объявлен раньше параметра, иначе «add»
      // будет разобран как идентификатор сервера.
      { path: 'servers/add', element: <AddServerPage /> },
      { path: 'servers/:id', element: <ServerDetailPage /> },

      { path: 'keys', element: <KeysPage /> },
      { path: 'keys/issue', element: <IssueKeyPage /> },

      { path: 'users', element: <UsersPage /> },
      { path: 'passcodes', element: <PassCodesPage /> },
      { path: 'notifications', element: <NotificationsPage /> },
      { path: 'logs', element: <LogsPage /> },
      { path: 'settings', element: <SettingsPage /> },

      { path: '*', element: <Navigate to="/servers" replace /> },
    ],
  },
]);
