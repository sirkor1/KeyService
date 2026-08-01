import type { ReactNode } from 'react';
import { cx } from './Btn';
import type { TagTone } from '@/lib/labels';

const TONE_CLASS: Record<TagTone, string> = {
  neutral: 'tag-neutral',
  outline: 'tag-outline',
  accent: 'tag-accent',
};

export function Tag({ tone, children }: { tone: TagTone; children: ReactNode }) {
  return <span className={cx('tag', TONE_CLASS[tone])}>{children}</span>;
}

/** Тег статуса из справочника подписей: подпись и тон задаются вместе. */
export function StatusTag({ status }: { status: { label: string; tone: TagTone } }) {
  return <Tag tone={status.tone}>{status.label}</Tag>;
}
