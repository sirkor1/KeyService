import { useState, type FormEvent } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { ApiError } from '@/api/client';
import { useAuth } from '@/auth/AuthProvider';
import { Spinner } from '@/components/Spinner';
import styles from './LoginPage.module.css';

/**
 * Экран входа. В макете его нет — спроектирован по правилам дизайн-системы:
 * блок прижат влево, без карточки, теней и иллюстраций; ошибка выводится
 * инлайново акцентом ступени 700 (акцент к фону даёт всего 3:1 и для мелкого
 * текста системой запрещён), а не тостом.
 */
export function LoginPage() {
  const { user, isLoading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: string } };

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (isLoading) return <Spinner label="Проверяем сессию…" />;

  if (user?.permissions.includes('panel:read')) {
    return <Navigate to={location.state?.from ?? '/servers'} replace />;
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await login(username, password);
      navigate(location.state?.from ?? '/servers', { replace: true });
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.status === 401
            ? 'Неверный логин или пароль.'
            : err.message
          : 'Не удалось выполнить вход.',
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className={styles.page}>
      <form className={styles.block} onSubmit={handleSubmit} aria-busy={submitting}>
        <div className={styles.brand}>AMNEZIA</div>
        <div className={styles.kicker}>Панель управления</div>

        <hr className="hr" />

        <h2 className={styles.title}>Вход</h2>

        <div className="field">
          <label htmlFor="login-username">Логин</label>
          <input
            id="login-username"
            className="input"
            autoComplete="username"
            autoFocus
            value={username}
            disabled={submitting}
            onChange={(event) => setUsername(event.target.value)}
          />
        </div>

        <div className="field">
          <label htmlFor="login-password">Пароль</label>
          <input
            id="login-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            disabled={submitting}
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>

        {error ? (
          <p className={styles.error} role="alert">
            {error}
          </p>
        ) : null}

        <button
          type="submit"
          className="btn btn-primary btn-block"
          disabled={submitting || !username || !password}
        >
          {submitting ? 'Входим…' : 'Войти'}
        </button>

        <p className={styles.note}>Доступ только для администраторов панели.</p>
      </form>
    </main>
  );
}
