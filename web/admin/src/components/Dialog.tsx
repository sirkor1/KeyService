import { useEffect, useRef, type ReactNode } from 'react';
import { Btn } from './Btn';

/**
 * Модальное окно дизайн-системы.
 *
 * Esc закрывает, фокус уходит внутрь при открытии — иначе с клавиатуры
 * до кнопок не добраться, а фон остаётся доступен для табуляции.
 */
export function Dialog({
  title,
  children,
  actions,
  onClose,
  closeDisabled = false,
}: {
  title: string;
  children: ReactNode;
  actions: ReactNode;
  onClose: () => void;
  /** Не даёт закрыть окно посреди необратимой мутации. */
  closeDisabled?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);

  // Callbacks из JSX часто имеют новую ссылку на каждом рендере. Жизненный
  // цикл фокуса не должен из-за этого считать обновление формы закрытием окна.
  onCloseRef.current = onClose;
  closeDisabledRef.current = closeDisabled;

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape' && !closeDisabledRef.current) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }

      if (event.key !== 'Tab') return;

      const focusable = getFocusable(ref.current);
      if (focusable.length === 0) {
        event.preventDefault();
        ref.current?.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!first || !last) return;
      // Если фокус вынесен расширением или скриптом за пределы окна,
      // следующий Tab возвращает его в диалог, а не в фон страницы.
      if (!ref.current?.contains(document.activeElement)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    returnFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    document.addEventListener('keydown', onKeyDown);
    const initial = ref.current?.querySelector<HTMLElement>('[data-dialog-initial-focus]');
    (initial ?? getFocusable(ref.current)[0] ?? ref.current)?.focus();

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      if (returnFocus.current?.isConnected) returnFocus.current.focus();
    };
  }, []);

  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      // Клик мимо окна закрывает, но только если это именно подложка,
      // а не всплывший клик изнутри диалога.
      onClick={(event) => {
        if (!closeDisabledRef.current && event.target === event.currentTarget) onCloseRef.current();
      }}
    >
      <div className="dialog" role="dialog" aria-modal="true" aria-label={title} ref={ref} tabIndex={-1}>
        <div className="dialog-title">{title}</div>
        <div className="dialog-body">{children}</div>
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>
  );
}

/** Диалог подтверждения необратимого действия. */
export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  busy,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Dialog
      title={title}
      onClose={onCancel}
      closeDisabled={busy}
      actions={
        <>
          <Btn variant="secondary" onClick={onCancel} disabled={busy}>
            Отмена
          </Btn>
          <Btn variant="primary" onClick={onConfirm} disabled={busy}>
            {busy ? 'Выполняем…' : confirmLabel}
          </Btn>
        </>
      }
    >
      {body}
    </Dialog>
  );
}

function getFocusable(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];

  return Array.from(
    container.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => !element.hasAttribute('hidden'));
}
