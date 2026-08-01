import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Link } from 'react-router-dom';

type Variant = 'primary' | 'secondary' | 'ghost';

const VARIANT_CLASS: Record<Variant, string> = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  ghost: 'btn-ghost',
};

/**
 * Кнопка дизайн-системы. Лейбл прижат влево — это правило системы,
 * применяется и когда кнопка шире текста (см. global.css).
 */
interface BtnProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  block?: boolean;
  children: ReactNode;
}

export function Btn({ variant = 'secondary', block, className, children, ...rest }: BtnProps) {
  return (
    <button
      type="button"
      className={cx('btn', VARIANT_CLASS[variant], block && 'btn-block', className)}
      {...rest}
    >
      {children}
    </button>
  );
}

/** Ссылка, выглядящая как кнопка: для переходов внутри панели. */
export function BtnLink({
  to,
  variant = 'secondary',
  className,
  children,
}: {
  to: string;
  variant?: Variant;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Link to={to} className={cx('btn', VARIANT_CLASS[variant], className)}>
      {children}
    </Link>
  );
}

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ');
}
