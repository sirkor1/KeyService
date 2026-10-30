import { useId } from 'react';
import type { XCoreRole } from '@/api/types';
import { XCORE_ENTRY_HINT, XCORE_ROLE_LABEL } from '@/lib/protocols';
import styles from './XCoreRoleField.module.css';

const ROLES: XCoreRole[] = ['exit', 'entry'];

/**
 * Выбор роли узла xcore. Общий для мастера добавления сервера и диалога «Добавить протокол»: роль выбирается
 * только при установке и потом не меняется, поэтому подсказка про вход стоит прямо под выбором.
 */
export function XCoreRoleField({ value, onChange, disabled, name }: {
  value: XCoreRole;
  onChange: (role: XCoreRole) => void;
  disabled?: boolean;
  /** Имя группы радиокнопок; у каждой группы на странице своё. */
  name: string;
}) {
  const hintId = useId();

  return (
    <fieldset className={styles.group} disabled={disabled} aria-describedby={value === 'entry' ? hintId : undefined}>
      <legend className={styles.legend}>Роль узла</legend>
      {ROLES.map((role) => (
        <label key={role} className={styles.option}>
          <input type="radio" name={name} value={role} checked={value === role} onChange={() => onChange(role)} />
          {XCORE_ROLE_LABEL[role]}
        </label>
      ))}
      {value === 'entry' ? <p id={hintId} className={styles.hint}>{XCORE_ENTRY_HINT}</p> : null}
    </fieldset>
  );
}
