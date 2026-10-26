import type { ReactNode } from 'react';
import type { BadgeModel } from '../lib/labels';

/** 상태 배지. 색 단독 금지 → 항상 텍스트 병기. */
export function Badge({ model }: { model: BadgeModel }) {
  return <span className={`badge ${model.cls}`}>{model.text}</span>;
}

export function BadgeText({ cls, children }: { cls: string; children: ReactNode }) {
  return <span className={`badge ${cls}`}>{children}</span>;
}
