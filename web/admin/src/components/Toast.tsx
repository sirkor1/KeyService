import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import styles from './Toast.module.css';

/** Время показа из макета. */
const TOAST_MS = 2200;

interface ToastContextValue {
  show: (message: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const show = useCallback((text: string) => {
    // Сбрасываем предыдущий таймер: иначе новое сообщение исчезнет
    // по расписанию старого.
    if (timer.current) clearTimeout(timer.current);

    setMessage(text);
    timer.current = setTimeout(() => setMessage(null), TOAST_MS);
  }, []);

  const value = useMemo(() => ({ show }), [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      {message ? (
        <div className={styles.toast} role="status" aria-live="polite">
          {message}
        </div>
      ) : null}
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast вызван вне ToastProvider.');
  return context;
}
