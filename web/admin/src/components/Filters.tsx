import { cx } from './Btn';
import styles from './Filters.module.css';

/** Поисковое поле над таблицей. */
export function SearchInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <input
      className={cx('input', styles.search)}
      type="search"
      value={value}
      placeholder={placeholder}
      aria-label={placeholder}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

export interface SegOption {
  value: string;
  label: string;
}

/** Сегментный переключатель дизайн-системы. */
export function Seg({
  name,
  value,
  options,
  onChange,
  disabled = false,
}: {
  name: string;
  value: string;
  options: SegOption[];
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  return (
    <div className="seg" role="radiogroup" aria-label={name}>
      {options.map((option) => (
        <label key={option.value} className="seg-opt">
          <input
            type="radio"
            name={name}
            value={option.value}
            checked={value === option.value}
            disabled={disabled}
            onChange={() => onChange(option.value)}
          />
          {option.label}
        </label>
      ))}
    </div>
  );
}

/** Строка фильтров: поиск слева, переключатель по центру, счётчик справа. */
export function FilterBar({
  children,
  shown,
  total,
}: {
  children: React.ReactNode;
  shown: number;
  total: number;
}) {
  return (
    <div className={styles.bar}>
      {children}
      <span className={styles.counter}>
        Показано {shown} из {total}
      </span>
    </div>
  );
}
