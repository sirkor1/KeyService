import { createContext, useCallback, useContext, useMemo, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError } from '@/api/client';
import { auth } from '@/api/endpoints';
import { qk } from '@/api/queryKeys';
import type { Me } from '@/api/types';

interface AuthContextValue {
  user: Me | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: qk.me,
    queryFn: ({ signal }) => auth.me(signal),
    // 401 здесь — не сбой, а «не вошёл». Повторять запрос бессмысленно.
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.isUnauthorized) && failureCount < 2,
    staleTime: 5 * 60 * 1000,
  });

  const loginMutation = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      auth.login(username, password),
    onSuccess: (response) => {
      queryClient.setQueryData(qk.me, response.user);
    },
  });

  const login = useCallback(
    async (username: string, password: string) => {
      await loginMutation.mutateAsync({ username, password });
    },
    [loginMutation],
  );

  const logout = useCallback(async () => {
    try {
      await auth.logout();
    } finally {
      // Кеш чистим в любом случае: если выход не дошёл до сервера,
      // держать в интерфейсе данные прошлого пользователя нельзя.
      queryClient.clear();
    }
  }, [queryClient]);

  const value = useMemo<AuthContextValue>(
    () => ({
      user: data ?? null,
      isLoading,
      login,
      logout,
      can: (permission: string) => Boolean(data?.permissions.includes(permission)),
    }),
    [data, isLoading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth вызван вне AuthProvider.');
  return context;
}
