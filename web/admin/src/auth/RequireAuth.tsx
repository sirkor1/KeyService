import { Navigate, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { useAuth } from './AuthProvider';
import { Spinner } from '@/components/Spinner';

/**
 * Пускает дальше только пользователей панели. Клиентские учётки VPN
 * получают тот же экран входа: панель для них не предназначена.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) return <Spinner label="Проверяем доступ…" />;

  if (!user || !user.permissions.includes('panel:read')) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }

  return <>{children}</>;
}
