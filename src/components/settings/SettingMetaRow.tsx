import { Info, RotateCcw } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import type { SettingLevel } from '../../config/settingsRegistry';
import { M3StatusBadge, M3Tooltip } from '../md3';

interface SettingMetaRowProps {
  id: string;
  level: SettingLevel;
  title: string;
  description?: string;
  defaultLabel: string;
  recommendedLabel?: string;
  rangeLabel?: string;
  impact: string;
  compatibility: string;
  requiresReconnect?: boolean;
  modified?: boolean;
  highlighted?: boolean;
  onReset?: () => void;
  control?: ReactNode;
  children?: ReactNode;
}

const LEVEL_META: Record<SettingLevel, { label: string; tone: 'neutral' | 'primary' | 'warning' }> = {
  basic: { label: 'Основной', tone: 'neutral' },
  advanced: { label: 'Расширенный', tone: 'primary' },
  expert: { label: 'Экспертный', tone: 'warning' },
};

export function SettingMetaRow({
  id,
  level,
  title,
  description,
  defaultLabel,
  recommendedLabel,
  rangeLabel,
  impact,
  compatibility,
  requiresReconnect = false,
  modified = false,
  highlighted = false,
  onReset,
  control,
  children,
}: SettingMetaRowProps) {
  const [infoOpen, setInfoOpen] = useState(false);
  const lvl = LEVEL_META[level];

  return (
    <div
      data-setting-id={id}
      className={`rounded-2xl border p-3.5 transition-colors ${
        highlighted
          ? 'border-[var(--md-primary)] bg-[var(--md-primary-container)]/20 ring-1 ring-[var(--md-primary)]'
          : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)]'
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[0.8rem] font-bold text-[var(--md-on-surface)]">{title}</span>
            <M3StatusBadge tone={lvl.tone} dot={false} className="px-1.5 py-0.5 text-[0.6rem]">
              {lvl.label}
            </M3StatusBadge>
            {requiresReconnect && (
              <M3Tooltip label="Изменение применится при следующем перезапуске активного VPN-туннеля">
                <span className="rounded-md bg-[var(--md-surface-container-highest)] px-1.5 py-0.5 text-[0.6rem] font-medium text-[var(--md-on-surface-variant)]">
                  Нужен реконнект
                </span>
              </M3Tooltip>
            )}
            {modified && (
              <span className="rounded-md bg-[var(--md-primary-container)] px-1.5 py-0.5 text-[0.6rem] font-semibold text-[var(--md-on-primary-container)]">
                Изменено
              </span>
            )}
            <button
              type="button"
              onClick={() => setInfoOpen((v) => !v)}
              aria-expanded={infoOpen}
              aria-label={`Справка по параметру: ${title}`}
              className={`inline-flex h-5 w-5 items-center justify-center rounded-full border text-[0.65rem] transition-colors ${
                infoOpen
                  ? 'border-[var(--md-primary)] bg-[var(--md-primary)] text-[var(--md-on-primary)]'
                  : 'border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface-variant)] hover:border-[var(--md-primary)] hover:text-[var(--md-on-surface)]'
              }`}
            >
              <Info className="h-3 w-3" />
            </button>
            {modified && onReset && (
              <M3Tooltip label={`Сбросить до значения по умолчанию (${defaultLabel})`}>
                <button
                  type="button"
                  onClick={onReset}
                  className="inline-flex items-center gap-1 rounded-full bg-[var(--md-surface-container-high)] px-2 py-0.5 text-[0.625rem] font-medium text-[var(--md-primary)] hover:brightness-110"
                >
                  <RotateCcw className="h-2.5 w-2.5" />
                  Сбросить
                </button>
              </M3Tooltip>
            )}
          </div>
          {description && (
            <p className="text-[0.72rem] leading-snug text-[var(--md-on-surface-variant)]">
              {description}
            </p>
          )}
        </div>
        {control && <div className="shrink-0">{control}</div>}
      </div>

      {infoOpen && (
        <div className="mt-2.5 grid grid-cols-1 gap-1.5 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] p-2.5 text-[0.6875rem] text-[var(--md-on-surface-variant)] sm:grid-cols-2">
          <div>
            <span className="font-semibold text-[var(--md-on-surface)]">По умолчанию:</span>{' '}
            <span className="font-mono-num">{defaultLabel}</span>
          </div>
          {recommendedLabel && (
            <div>
              <span className="font-semibold text-[var(--md-on-surface)]">Рекомендуется:</span>{' '}
              <span className="font-mono-num text-[var(--md-success)]">{recommendedLabel}</span>
            </div>
          )}
          {rangeLabel && (
            <div>
              <span className="font-semibold text-[var(--md-on-surface)]">Допустимо:</span>{' '}
              <span className="font-mono-num">{rangeLabel}</span>
            </div>
          )}
          <div>
            <span className="font-semibold text-[var(--md-on-surface)]">Совместимость:</span>{' '}
            {compatibility}
          </div>
          <div className="sm:col-span-2">
            <span className="font-semibold text-[var(--md-on-surface)]">На что влияет:</span>{' '}
            {impact}
          </div>
        </div>
      )}

      {children && <div className="mt-3">{children}</div>}
    </div>
  );
}
