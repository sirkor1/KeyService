import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from 'react-router-dom';
import { ApiError } from '@/api/client';
import { AuthProvider } from '@/auth/AuthProvider';
import { ToastProvider } from '@/components/Toast';
import { router } from '@/router';

// Порядок важен: дизайн-система первой, поверх неё проектные токены,
// затем глобальные правила, которые кое-что в ней переопределяют.
import '@/styles/ds/styles.css';
import '@/styles/tokens.css';
import '@/styles/global.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Повторять запрос, отклонённый по правам или из-за отсутствия сессии,
      // бессмысленно — ответ не изменится.
      retry: (failureCount, error) => {
        if (error instanceof ApiError && (error.isUnauthorized || error.isForbidden)) return false;
        return failureCount < 2;
      },
      staleTime: 15_000,
      refetchOnWindowFocus: false,
    },
  },
});

const container = document.getElementById('root');
if (!container) throw new Error('Не найден корневой элемент #root.');

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <RouterProvider router={router} />
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
