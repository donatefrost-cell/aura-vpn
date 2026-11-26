import {
  AlertTriangle,
  Calendar,
  Check,
  ChevronDown,
  Globe,
  History,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Rss,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { useState } from 'react';
import {
  M3Button,
  M3Dialog,
  M3EmptyState,
  M3IconButton,
  M3ProgressBar,
  M3Select,
  M3StatusBadge,
  M3SurfaceCard,
  M3Switch,
  M3Tooltip,
} from '../components/md3';
import type { ServerProfile, Subscription, SubscriptionRefreshDiff } from '../types/vpn';
import { formatBytes, formatExpireDate, formatRelativeDate } from '../utils/format';

interface SubscriptionsViewProps {
  subscriptions: Subscription[];
  profiles: ServerProfile[];
  refreshingIds: Set<string>;
  lastRefreshDiff?: SubscriptionRefreshDiff | null;
  onRefresh: (id: string) => void;
  onRollback?: (id: string) => void;
  onRefreshAll: () => void;
  onRename: (id: string, title: string) => void;
  onToggleEnabled: (id: string, enabled: boolean) => void;
  onUpdateConfig: (id: string, autoUpdate: boolean, intervalHours: number | null) => void;
  onDelete: (id: string) => void;
  onOpenImport: () => void;
}

function getSafeMaskedDomain(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname;
  } catch {
    return 'HTTPS-подписка';
  }
}

export function SubscriptionsView({
  subscriptions,
  profiles,
  refreshingIds,
  lastRefreshDiff,
  onRefresh,
  onRollback,
  onRefreshAll,
  onRename,
  onToggleEnabled,
  onUpdateConfig,
  onDelete,
  onOpenImport,
}: SubscriptionsViewProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftTitle, setDraftTitle] = useState('');
  const [expandedSyncHistory, setExpandedSyncHistory] = useState<Set<string>>(new Set());
  const [expandedErrorHistory, setExpandedErrorHistory] = useState<Set<string>>(new Set());
  const [pendingDelete, setPendingDelete] = useState<Subscription | null>(null);

  const isAnyRefreshing = refreshingIds.size > 0;

  const commitRename = (id: string) => {
    const trimmed = draftTitle.trim();
    if (trimmed) onRename(id, trimmed);
    setEditingId(null);
  };

  const toggleSyncHistory = (id: string) => {
    setExpandedSyncHistory((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleErrorHistory = (id: string) => {
    setExpandedErrorHistory((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-3">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-display text-lg font-bold tracking-tight text-[var(--md-on-surface)]">
              Подписки
            </h1>
            <M3StatusBadge tone="neutral">{subscriptions.length}</M3StatusBadge>
          </div>
          <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
            Управление источниками узлов, интервалами синхронизации и квотами трафика
          </p>
        </div>

        <div className="flex items-center gap-2">
          {subscriptions.length > 0 && (
            <M3Button
              variant="outlined"
              size="sm"
              onClick={onRefreshAll}
              disabled={isAnyRefreshing}
              leadingIcon={
                <RefreshCw className={`h-3.5 w-3.5 ${isAnyRefreshing ? 'animate-spin' : ''}`} />
              }
            >
              Обновить все
            </M3Button>
          )}
          <M3Button
            variant="filled"
            size="sm"
            onClick={onOpenImport}
            leadingIcon={<Plus className="h-3.5 w-3.5" />}
          >
            Добавить подписку
          </M3Button>
        </div>
      </div>

      {/* Empty State */}
      {subscriptions.length === 0 ? (
        <M3EmptyState
          icon={<Rss className="h-7 w-7" />}
          title="Нет активных подписок"
          description="Добавьте одну или несколько HTTPS-подписок в окне импорта. Приложение автоматически загрузит узлы, лимит трафика и срок действия."
          action={
            <M3Button
              variant="filled"
              onClick={onOpenImport}
              leadingIcon={<Plus className="h-4 w-4" />}
            >
              Добавить подписку
            </M3Button>
          }
        />
      ) : (
        <div className="space-y-2.5">
          {subscriptions.map((sub) => {
            const subProfiles = profiles.filter((p) => p.subscriptionId === sub.id);
            const reachableCount = subProfiles.filter(
              (p) => p.latencyMs !== null && p.latencyMs !== undefined,
            ).length;
            const refreshing = refreshingIds.has(sub.id);
            const isEditing = editingId === sub.id;

            const ui = sub.userInfo;
            const total = ui?.totalBytes ?? 0;
            const used = (ui?.uploadBytes ?? 0) + (ui?.downloadBytes ?? 0);
            const hasQuota = total > 0;
            const exactPct = hasQuota ? Math.max(0, Math.min(100, (used / total) * 100)) : 0;
            const percent = Math.round(exactPct);
            const remainingBytes = hasQuota ? Math.max(0, total - used) : null;
            const usedPctLabel =
              used > 0 && exactPct < 1
                ? '<1%'
                : used < total && exactPct >= 99.5
                  ? '99.9%'
                  : `${percent}%`;
            const remainingPctLabel =
              used > 0 && exactPct < 1
                ? '>99%'
                : used < total && exactPct >= 99.5
                  ? '<1%'
                  : `${100 - percent}%`;
            const isQuotaLow = hasQuota && percent >= 85;
            const expireFormatted = formatExpireDate(ui?.expireTimestamp);
            const daysLeft =
              ui?.expireTimestamp && ui.expireTimestamp > 0
                ? Math.ceil((ui.expireTimestamp * 1000 - Date.now()) / 86_400_000)
                : null;
            const isExpiringSoon = daysLeft !== null && daysLeft <= 5;

            const standardIntervals = [1, 3, 6, 12, 24, 48, 72, 168];
            const rawHours = sub.updateIntervalHours;
            const currentInterval =
              !sub.autoUpdate || !rawHours || rawHours <= 0
                ? 'off'
                : standardIntervals.includes(rawHours)
                  ? String(rawHours)
                  : `custom-${rawHours}`;
            const intervalOptions = [
              { value: 'off', label: 'Авто: Выкл' },
              { value: '1', label: 'Авто: 1 ч' },
              { value: '3', label: 'Авто: 3 ч' },
              { value: '6', label: 'Авто: 6 ч' },
              { value: '12', label: 'Авто: 12 ч' },
              { value: '24', label: 'Авто: 24 ч' },
              { value: '48', label: 'Авто: 48 ч' },
              { value: '72', label: 'Авто: 72 ч' },
              { value: '168', label: 'Авто: 7 дн' },
              ...(rawHours && rawHours > 0 && !standardIntervals.includes(rawHours)
                ? [{ value: `custom-${rawHours}`, label: `Авто: ${rawHours} ч` }]
                : []),
            ];
            const syncHistoryOpen = expandedSyncHistory.has(sub.id);
            const errorHistoryOpen = expandedErrorHistory.has(sub.id);
            const activeDiff =
              lastRefreshDiff && lastRefreshDiff.subscriptionId === sub.id ? lastRefreshDiff : null;

            return (
              <M3SurfaceCard
                key={sub.id}
                level="default"
                className={`p-3.5 transition-opacity ${sub.enabled ? '' : 'opacity-75'}`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  {/* Left: Switch + Title + Masked domain + Badges */}
                  <div className="flex min-w-0 flex-1 items-start gap-3">
                    <div className="pt-0.5">
                      <M3Switch
                        checked={sub.enabled}
                        onChange={(next) => onToggleEnabled(sub.id, next)}
                        ariaLabel={`Включить подписку ${sub.title}`}
                      />
                    </div>

                    <div className="min-w-0 flex-1">
                      {isEditing ? (
                        <div className="flex items-center gap-1.5">
                          <input
                            value={draftTitle}
                            onChange={(e) => setDraftTitle(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') commitRename(sub.id);
                              if (e.key === 'Escape') setEditingId(null);
                            }}
                            autoFocus
                            className="h-8 w-64 rounded-xl border border-[var(--md-primary)] bg-[var(--md-surface)] px-2.5 text-[0.8125rem] font-semibold text-[var(--md-on-surface)]"
                          />
                          <M3IconButton
                            size="sm"
                            variant="tonal"
                            onClick={() => commitRename(sub.id)}
                            aria-label="Сохранить"
                          >
                            <Check className="h-3.5 w-3.5" />
                          </M3IconButton>
                          <M3IconButton
                            size="sm"
                            onClick={() => setEditingId(null)}
                            aria-label="Отмена"
                          >
                            <X className="h-3.5 w-3.5" />
                          </M3IconButton>
                        </div>
                      ) : (
                        <div className="flex flex-wrap items-center gap-2">
                          <h2 className="truncate text-[0.875rem] font-bold text-[var(--md-on-surface)]">
                            {sub.title}
                          </h2>
                          <M3Tooltip label="Переименовать подписку">
                            <button
                              type="button"
                              onClick={() => {
                                setEditingId(sub.id);
                                setDraftTitle(sub.title);
                              }}
                              aria-label="Переименовать подписку"
                              className="rounded-lg p-1 text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container-highest)] hover:text-[var(--md-on-surface)]"
                            >
                              <Pencil className="h-3 w-3" />
                            </button>
                          </M3Tooltip>

                          <M3StatusBadge tone={sub.enabled ? 'primary' : 'neutral'} className="font-mono-num">
                            {subProfiles.length} узл.
                            {reachableCount > 0 ? ` • ${reachableCount} доступно` : ''}
                          </M3StatusBadge>

                          {!sub.enabled && (
                            <M3StatusBadge tone="warning">Скрыта из серверов</M3StatusBadge>
                          )}

                          {isQuotaLow && (
                            <M3StatusBadge tone={percent >= 95 ? 'error' : 'warning'} className="font-mono-num">
                              Трафик {percent}%
                            </M3StatusBadge>
                          )}

                          {isExpiringSoon && (
                            <M3StatusBadge tone={daysLeft <= 0 ? 'error' : 'warning'} className="font-mono-num">
                              {daysLeft <= 0 ? 'Срок истёк' : `Осталось ${daysLeft} дн.`}
                            </M3StatusBadge>
                          )}
                        </div>
                      )}

                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.72rem] text-[var(--md-on-surface-variant)]">
                        <M3Tooltip label="Секретный токен ссылки подписки скрыт">
                          <span className="inline-flex items-center gap-1">
                            <Globe className="h-3 w-3" />
                            {getSafeMaskedDomain(sub.url)}
                          </span>
                        </M3Tooltip>
                        <span>Обновлено: {formatRelativeDate(sub.updatedAt)}</span>
                        {expireFormatted && (
                          <span className="inline-flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            До {expireFormatted}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Right: Auto-update selector + Refresh + Delete */}
                  <div className="flex shrink-0 items-center gap-2">
                    <M3Select
                      size="sm"
                      align="right"
                      ariaLabel="Интервал автообновления подписки"
                      value={currentInterval}
                      onChange={(val) => {
                        if (val === 'off') {
                          onUpdateConfig(sub.id, false, sub.updateIntervalHours ?? 12);
                        } else if (val.startsWith('custom-')) {
                          onUpdateConfig(sub.id, true, Number(val.slice(7)));
                        } else {
                          onUpdateConfig(sub.id, true, Number(val));
                        }
                      }}
                      options={intervalOptions}
                    />

                    <M3Button
                      variant="tonal"
                      size="sm"
                      loading={refreshing}
                      loadingText="Загрузка"
                      onClick={() => onRefresh(sub.id)}
                      leadingIcon={<RefreshCw className="h-3.5 w-3.5" />}
                    >
                      Обновить
                    </M3Button>

                    <M3IconButton
                      size="sm"
                      tooltip="Удалить подписку"
                      onClick={() => setPendingDelete(sub)}
                      aria-label="Удалить подписку"
                      className="text-[var(--md-error)] hover:bg-[var(--md-error-container)]"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </M3IconButton>
                  </div>
                </div>

                {/* Quota Bar (only when panel returns totalBytes) */}
                {hasQuota ? (
                  <div className="mt-3 rounded-xl bg-[var(--md-surface-container-low)] px-3 py-2">
                    <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-[0.72rem] font-mono-num">
                      <span className="font-medium text-[var(--md-on-surface)]">
                        Использовано {formatBytes(used)} из {formatBytes(total)} ({usedPctLabel})
                      </span>
                      <span className="text-[var(--md-on-surface-variant)]">
                        Осталось: {formatBytes(remainingBytes ?? 0)} ({remainingPctLabel})
                      </span>
                    </div>
                    <M3ProgressBar
                      percent={exactPct}
                      tone={percent >= 95 ? 'error' : percent >= 80 ? 'warning' : 'primary'}
                    />
                  </div>
                ) : (
                  <div className="mt-2.5 flex items-center gap-1.5 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                    <ShieldCheck className="h-3.5 w-3.5 text-[var(--md-on-surface-variant)]" />
                    <span>Провайдер подписки не передаёт данные о лимите трафика.</span>
                  </div>
                )}

                {/* Subscription Diff + Rollback Banner */}
                {activeDiff && (
                  <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--md-primary)]/30 bg-[var(--md-primary-container)]/35 px-3 py-2 text-[0.72rem]">
                    <div className="space-y-0.5">
                      <div className="font-semibold text-[var(--md-on-surface)] font-mono-num">
                        Изменения обновления: +{activeDiff.added} добавлено / -{activeDiff.removed} удалено / ~{activeDiff.updated} обновлено
                      </div>
                      {(activeDiff.warnings ?? []).map((w, idx) => (
                        <div key={idx} className="text-[0.6875rem] text-[var(--md-warning)]">
                          • {w}
                        </div>
                      ))}
                    </div>
                    {activeDiff.canRollback && onRollback && (
                      <M3Button
                        size="sm"
                        variant="tonal"
                        leadingIcon={<RotateCcw className="h-3.5 w-3.5" />}
                        onClick={() => onRollback(sub.id)}
                      >
                        Откатить узлы
                      </M3Button>
                    )}
                  </div>
                )}

                {/* Sync History (v0.8.0) */}
                {sub.syncHistory && sub.syncHistory.length > 0 && (
                  <div className="mt-2.5 rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2">
                    <div className="flex items-center justify-between gap-2 text-[0.7rem]">
                      <span className="font-semibold text-[var(--md-on-surface)]">
                        История синхронизаций ({sub.syncHistory.length})
                      </span>
                      <button
                        type="button"
                        onClick={() => toggleSyncHistory(sub.id)}
                        className="inline-flex items-center gap-1 rounded-lg px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-primary)] hover:bg-[var(--md-surface)]/40"
                      >
                        <History className="h-3 w-3" />
                        {syncHistoryOpen ? 'Скрыть' : 'Показать'}
                      </button>
                    </div>
                    {syncHistoryOpen && (
                      <div className="mt-2 space-y-1 border-t border-[var(--md-outline-variant)]/50 pt-2">
                        {sub.syncHistory.slice(0, 8).map((sy) => (
                          <div
                            key={sy.id}
                            className="flex flex-wrap items-center justify-between gap-2 text-[0.6875rem]"
                          >
                            <div className="flex items-center gap-1.5">
                              <M3StatusBadge
                                tone={
                                  sy.status === 'error'
                                    ? 'error'
                                    : sy.status === 'rollback'
                                      ? 'warning'
                                      : 'success'
                                }
                                dot={false}
                              >
                                {sy.status === 'error'
                                  ? 'Ошибка'
                                  : sy.status === 'rollback'
                                    ? 'Откат'
                                    : 'Успешно'}
                              </M3StatusBadge>
                              <span className="font-mono-num text-[var(--md-on-surface)]">
                                {sy.status === 'error'
                                  ? sy.errorMessage ?? 'Ошибка'
                                  : `Узлов: ${sy.serverCount} (+${sy.added}/-${sy.removed}/~${sy.updated})`}
                              </span>
                            </div>
                            <span className="font-mono-num text-[0.625rem] text-[var(--md-on-surface-variant)]">
                              {formatRelativeDate(sy.timestamp)} • {sy.durationMs} мс
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Errors & Error History Accordion */}
                {(sub.lastError || sub.errorHistory.length > 0) && (
                  <div className="mt-2.5 rounded-xl border border-[var(--md-error)]/30 bg-[var(--md-error-container)]/50 px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 text-[0.72rem] font-medium text-[var(--md-error)]">
                        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate">
                          {sub.lastError ?? 'Зафиксированы ошибки при предыдущих обновлениях'}
                        </span>
                      </div>
                      {sub.errorHistory.length > 0 && (
                        <button
                          type="button"
                          onClick={() => toggleErrorHistory(sub.id)}
                          className="inline-flex shrink-0 items-center gap-1 rounded-lg px-2 py-0.5 text-[0.6875rem] font-medium text-[var(--md-on-surface)] hover:bg-[var(--md-surface)]/40"
                        >
                          <History className="h-3 w-3" />
                          Журнал ({sub.errorHistory.length})
                          <ChevronDown
                            className={`h-3 w-3 transition-transform ${
                              errorHistoryOpen ? 'rotate-180' : ''
                            }`}
                          />
                        </button>
                      )}
                    </div>

                    {errorHistoryOpen && sub.errorHistory.length > 0 && (
                      <div className="mt-2 space-y-1 border-t border-[var(--md-error)]/20 pt-2">
                        {sub.errorHistory.map((entry, idx) => (
                          <div
                            key={`${entry.timestamp}-${idx}`}
                            className="flex items-start justify-between gap-2 text-[0.6875rem] text-[var(--md-on-surface)]"
                          >
                            <span className="truncate">{entry.message}</span>
                            <span className="shrink-0 font-mono-num text-[0.625rem] opacity-70">
                              {formatRelativeDate(entry.timestamp)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </M3SurfaceCard>
            );
          })}
        </div>
      )}

      {/* Delete confirmation dialog */}
      <M3Dialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        title="Удалить подписку?"
        description={
          pendingDelete
            ? `Подписка «${pendingDelete.title}» и все связанные с ней серверы (${
                profiles.filter((p) => p.subscriptionId === pendingDelete.id).length
              } шт.) будут удалены.`
            : undefined
        }
        footer={
          <>
            <M3Button variant="text" onClick={() => setPendingDelete(null)}>
              Отмена
            </M3Button>
            <M3Button
              variant="danger"
              onClick={() => {
                if (pendingDelete) onDelete(pendingDelete.id);
                setPendingDelete(null);
              }}
            >
              Удалить
            </M3Button>
          </>
        }
      >
        <p className="text-[0.75rem] text-[var(--md-on-surface-variant)]">
          Это действие удалит локальный профиль подписки. Внешний аккаунт на сервере провайдера не затрагивается.
        </p>
      </M3Dialog>
    </div>
  );
}
