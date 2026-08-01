import { cx } from '@/components/Btn';
import styles from './AddServerPage.module.css';

const STEPS = [
  { num: 1, label: 'Основное', hint: 'имя, адрес, порт' },
  { num: 2, label: 'Доступ', hint: 'SSH и ключ' },
  { num: 3, label: 'Протоколы', hint: 'порты и параметры' },
  { num: 4, label: 'Установка', hint: 'проверка и запуск' },
];

/**
 * Полоса шагов. Назад ходить можно, вперёд — только кнопкой,
 * чтобы не проскочить незаполненные поля.
 */
export function Stepper({
  current,
  maxReached,
  onGoTo,
  disabled = false,
}: {
  current: number;
  maxReached: number;
  onGoTo: (step: number) => void;
  disabled?: boolean;
}) {
  return (
    <div className={styles.stepper}>
      {STEPS.map((step) => {
        const reachable = step.num <= maxReached;

        return (
          <button
            key={step.num}
            type="button"
            className={cx(styles.step, step.num === current && styles.stepActive)}
            disabled={disabled || !reachable}
            onClick={() => !disabled && reachable && onGoTo(step.num)}
          >
            <span className={styles.stepNum}>Шаг {step.num}</span>
            <span className={styles.stepLabel}>{step.label}</span>
            <span className={styles.stepHint}>{step.hint}</span>
          </button>
        );
      })}
    </div>
  );
}
