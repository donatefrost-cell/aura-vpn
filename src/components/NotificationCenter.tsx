import {
  AlertCircle,
  Bell,
  BellOff,
  CheckCheck,
  CheckCircle2,
  ExternalLink,
  Info,
  Trash2,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useRef, useState } from 'react';
import { notificationStore, useNotifications } from '../stores/notificationStore';
import type { AppNotification, NotificationCategory } from '../types/vpn';
import { M3Chip, M3IconButton, M3Tooltip } from './md3';

const CATEGORY_META: Array<{ id: NotificationCategory; label: string }> = [
  { id: 'connection', label: 'Сеть' },
  { id: 'subscription', label: 'Подписки' },
  { id: 'import', label: 'Импорт' },
  { id: 'duplicate', label: 'Дубли' },
  { id: 'update', label: 'Обновления' },
];

function formatNotifTime(ts: number): string {
  return new Date(ts).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
}

interface NotificationCenterProps {
  onNavigate?: (link: NonNullable<AppNotification['deepLink']>) => void;
}

export function NotificationCenter({ onNavigate }: NotificationCenterProps) {
  const [open, setOpen] = useState(false);
  const { items, mutedCategories } = useNotifications();
  const containerRef = useRef<HTMLDivElement>(null);

  const unreadCount = items.reduce((acc, item) => acc + (item.read ? 0 : 1), 0);

  useEffect(() => {
    if (!open) return;
    const onOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    window.addEventListener('mousedown', onOutside);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('mousedown', onOutside);
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative inline-flex">
      <M3Tooltip label="Центр уведомлений">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-label="Центр уведомлений"
          aria-expanded={open}
          data-testid="notification-bell"
          className="relative flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]"
        >
          <Bell className="h-3.5 w-3.5" />
          {unreadCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 flex h-3.5 min-w-3.5 items-center justify-center rounded-full bg-[var(--md-primary)] px-1 text-[0.5625rem] font-bold text-[var(--md-on-primary)] font-mono-num">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </button>
      </M3Tooltip>

      <AnimatePresence>
        {open && (
          <motion.div
            role="dialog"
            aria-label="История уведомлений"
            initial={{ opacity: 0, y: -6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.97 }}
            transition={{ duration: 0.14 }}
            className="fixed top-10.5 right-3 z-[70] w-[352px] max-w-[calc(100vw-24px)] rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] p-3 shadow-2xl"
          >
            <div className="flex items-center justify-between gap-2 pb-2 border-b border-[var(--md-outline-variant)]">
              <div className="flex items-center gap-2">
                <span className="font-display text-[0.8125rem] font-bold text-[var(--md-on-surface)]">
                  Уведомления
                </span>
                {unreadCount > 0 && (
                  <span className="rounded-full bg-[var(--md-primary-container)] px-1.5 py-0.5 text-[0.625rem] font-semibold text-[var(--md-on-primary-container)] font-mono-num">
                    {unreadCount}
                  </span>
                )}
              </div>

              <div className="flex items-center gap-1">
                {unreadCount > 0 && (
                  <M3IconButton
                    size="sm"
                    tooltip="Отметить все прочитанными"
                    onClick={() => notificationStore.markAllRead()}
                  >
                    <CheckCheck className="h-3.5 w-3.5" />
                  </M3IconButton>
                )}
                {items.length > 0 && (
                  <M3IconButton
                    size="sm"
                    tooltip="Очистить историю"
                    onClick={() => notificationStore.clear()}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </M3IconButton>
                )}
              </div>
            </div>

            <div className="mt-2 flex flex-wrap gap-1">
              {CATEGORY_META.map((cat) => {
                const muted = Boolean(mutedCategories[cat.id]);
                return (
                  <M3Chip
                    key={cat.id}
                    active={!muted}
                    tooltip={
                      muted
                        ? `Категория «${cat.label}» заглушена — нажмите для включения`
                        : `Нажмите, чтобы отключить уведомления категории «${cat.label}»`
                    }
                    onClick={() => notificationStore.toggleMute(cat.id)}
                    className="px-2 py-0.5 text-[0.65rem]"
                    leading={
                      muted ? <BellOff className="h-2.5 w-2.5" /> : undefined
                    }
                  >
                    {cat.label}
                  </M3Chip>
                );
              })}
            </div>

            <div className="aura-scroll mt-2.5 max-h-[300px] space-y-1.5 overflow-y-auto pr-0.5">
              {items.length === 0 ? (
                <div className="py-8 text-center text-[0.75rem] text-[var(--md-on-surface-variant)]">
                  История уведомлений пуста
                </div>
              ) : (
                items.map((n) => {
                  const Icon =
                    n.tone === 'success'
                      ? CheckCircle2
                      : n.tone === 'error' || n.tone === 'warning'
                        ? AlertCircle
                        : Info;
                  const iconColor =
                    n.tone === 'success'
                      ? 'text-[var(--md-success)]'
                      : n.tone === 'error'
                        ? 'text-[var(--md-error)]'
                        : n.tone === 'warning'
                          ? 'text-[var(--md-warning)]'
                          : 'text-[var(--md-primary)]';

                  return (
                    <div
                      key={n.id}
                      onClick={() => {
                        notificationStore.markRead(n.id);
                        if (n.deepLink && onNavigate) {
                          onNavigate(n.deepLink);
                          setOpen(false);
                        }
                      }}
                      className={`group flex items-start gap-2 rounded-xl border px-2.5 py-2 transition-colors ${
                        n.deepLink ? 'cursor-pointer' : ''
                      } ${
                        n.read
                          ? 'border-[var(--md-outline-variant)]/50 bg-[var(--md-surface-container)] opacity-80'
                          : 'border-[var(--md-primary)]/35 bg-[var(--md-surface-container-low)]'
                      }`}
                    >
                      <Icon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${iconColor}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-[0.75rem] font-semibold text-[var(--md-on-surface)]">
                            {n.title}
                          </span>
                          <span className="shrink-0 text-[0.625rem] text-[var(--md-on-surface-variant)] font-mono-num">
                            {formatNotifTime(n.createdAt)}
                          </span>
                        </div>
                        {n.description && (
                          <div className="mt-0.5 line-clamp-2 text-[0.6875rem] leading-snug text-[var(--md-on-surface-variant)]">
                            {n.description}
                          </div>
                        )}
                        {n.deepLink && (
                          <div className="mt-1 inline-flex items-center gap-1 text-[0.65rem] font-medium text-[var(--md-primary)]">
                            <span>Перейти</span>
                            <ExternalLink className="h-2.5 w-2.5" />
                          </div>
                        )}
                      </div>
                      <button
                        type="button"
                        aria-label="Удалить уведомление"
                        onClick={(e) => {
                          e.stopPropagation();
                          notificationStore.remove(n.id);
                        }}
                        className="shrink-0 rounded-lg p-1 text-[var(--md-on-surface-variant)] opacity-0 transition-opacity group-hover:opacity-100 hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-error)]"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
