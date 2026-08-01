import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { cx } from './Btn';
import styles from './Table.module.css';

/**
 * Колонка таблицы.
 *
 * width задаётся всегда и намеренно: реальные данные — 44-символьные
 * base64-ключи, длинные хостнеймы, длинные русские имена — разносят
 * аккуратную вёрстку макета. Значения обрезаются многоточием, полный
 * текст доступен в title.
 */
export interface Column<T> {
  key: string;
  header: string;
  /**
   * Ширина колонки в процентах. Единственное место, где остался инлайновый
   * стиль: ширины задаются данными, а не разметкой. Проценты, а не пиксели —
   * иначе сработает правило дизайн-системы о сырых px в литералах.
   */
  width?: `${number}%`;
  align?: 'left' | 'right';
  /** Отключает обрезку: для ячеек со сложной разметкой. */
  noEllipsis?: boolean;
  render: (row: T) => ReactNode;
  /** Полный текст для подсказки, если ячейка обрезана. */
  title?: (row: T) => string | undefined;
}

interface TableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** Делает строку кликабельной. */
  rowHref?: (row: T) => string;
  empty?: ReactNode;
}

export function Table<T>({ columns, rows, rowKey, rowHref, empty }: TableProps<T>) {
  const navigate = useNavigate();

  if (rows.length === 0) {
    return <div className={styles.empty} role="status">{empty ?? 'Ничего не найдено.'}</div>;
  }

  return (
    <div className={styles.scroll}>
      <table className="table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                className={cx(column.align === 'right' && styles.right)}
                style={column.width ? { width: column.width } : undefined}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const href = rowHref?.(row);
            return (
              <tr
                key={rowKey(row)}
                className={cx(href && styles.clickable)}
                onClick={href ? () => navigate(href) : undefined}
                onKeyDown={
                  href
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          navigate(href);
                        }
                      }
                    : undefined
                }
                tabIndex={href ? 0 : undefined}
                aria-label={href ? `Открыть ${columns[0]?.title?.(row) ?? rowKey(row)}` : undefined}
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cx(
                      column.align === 'right' && styles.right,
                      !column.noEllipsis && styles.truncate,
                    )}
                    title={column.title?.(row)}
                  >
                    {column.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
