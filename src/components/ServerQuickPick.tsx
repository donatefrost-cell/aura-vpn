import { Check, ChevronDown, Gauge, RefreshCw, Search, Sliders, Star, X, Zap } from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ServerProfile } from '../types/vpn';
import {
  formatNodePoolLabel,
  formatProtocolBadge,
  formatServerDisplayName,
  getCountryName,
  getLatencyTone,
  getProfileNodeCount,
  shouldShowCountryInSubtitle,
} from '../utils/format';
import { CountryBadge } from './CountryBadge';
import { M3Tooltip } from './md3';

interface ServerQuickPickProps {
  profiles: ServerProfile[];
  activeServer: ServerProfile | null;
  isBusy: boolean;
  onSelectServer: (id: string) => void;
  onPingActive: (id: string) => void;
  onAutoSelectFastest: () => void;
  isPinging: boolean;
  isAutoSelecting?: boolean;
  onInspectActive?: (id: string) => void;
}

export function ServerQuickPick({
  profiles,
  activeServer,
  isBusy,
  onSelectServer,
  onPingActive,
  onAutoSelectFastest,
  isPinging,
  isAutoSelecting,
  onInspectActive,
}: ServerQuickPickProps) {
  const [open, setOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      setSearchQuery('');
      return;
    }
    const onOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        setOpen(false);
      }
    };
    window.addEventListener('mousedown', onOutside);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('mousedown', onOutside);
      window.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const sortedProfiles = useMemo(() => {
    return [...profiles].sort((a, b) => Number(b.favorite) - Number(a.favorite));
  }, [profiles]);

  const filteredProfiles = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return sortedProfiles;
    return sortedProfiles.filter((srv) => {
      const cname = getCountryName(srv.countryCode)?.toLowerCase() ?? '';
      const proto = formatProtocolBadge(srv).toLowerCase();
      return (
        srv.name.toLowerCase().includes(q) ||
        cname.includes(q) ||
        (srv.countryCode?.toLowerCase().includes(q) ?? false) ||
        proto.includes(q)
      );
    });
  }, [sortedProfiles, searchQuery]);

  if (!activeServer) return null;

  const latencyTone = getLatencyTone(activeServer.latencyMs);
  const latencyColor =
    latencyTone === 'good'
      ? 'text-[var(--md-success)]'
      : latencyTone === 'medium'
        ? 'text-[var(--md-warning)]'
        : latencyTone === 'poor'
          ? 'text-[var(--md-error)]'
          : 'text-[var(--md-on-surface-variant)]';

  const activeDisplayName = formatServerDisplayName(activeServer.name, activeServer.countryCode);
  const activeCountryName = getCountryName(activeServer.countryCode);
  const activeNodeCount = getProfileNodeCount(activeServer);
  const activeSubtitleParts = [
    shouldShowCountryInSubtitle(activeDisplayName, activeCountryName) ? activeCountryName : null,
    formatProtocolBadge(activeServer),
    activeNodeCount > 1 ? formatNodePoolLabel(activeNodeCount) : null,
  ].filter((part): part is string => Boolean(part));

  return (
    <div ref={containerRef} className="relative w-full">
      <div className="flex items-center gap-2 rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3 py-2 transition-colors hover:border-[var(--md-primary)]/45">
        <button
          type="button"
          aria-haspopup="listbox"
          aria-expanded={open}
          disabled={isBusy}
          onClick={() => setOpen((v) => !v)}
          className="flex min-w-0 flex-1 items-center justify-between gap-3 text-left disabled:opacity-60"
        >
          <div className="flex min-w-0 items-center gap-3">
            <CountryBadge code={activeServer.countryCode} size="lg" />
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 truncate text-[0.84375rem] font-semibold text-[var(--md-on-surface)]">
                {activeServer.favorite && (
                  <Star className="h-3.5 w-3.5 shrink-0 fill-[var(--md-warning)] text-[var(--md-warning)]" />
                )}
                <M3Tooltip label={activeDisplayName} className="min-w-0 max-w-full">
                  <span className="truncate block">{activeDisplayName}</span>
                </M3Tooltip>
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[0.6875rem] text-[var(--md-on-surface-variant)]">
                {activeSubtitleParts.map((part, idx) => (
                  <span key={`${part}-${idx}`} className="inline-flex items-center gap-1.5">
                    {idx > 0 && <span className="opacity-50">•</span>}
                    <span>{part}</span>
                  </span>
                ))}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <M3Tooltip label="Задержка TCP-рукопожатия до узла (не скорость туннеля)">
              <div
                className={`flex items-center gap-1 text-[0.72rem] font-medium font-mono-num ${latencyColor}`}
              >
                <Gauge className="h-3.5 w-3.5" />
                {activeServer.latencyMs !== null && activeServer.latencyMs !== undefined
                  ? `TCP ${activeServer.latencyMs} мс`
                  : '—'}
              </div>
            </M3Tooltip>
            <ChevronDown
              className={`h-4 w-4 text-[var(--md-on-surface-variant)] transition-transform duration-150 ${
                open ? 'rotate-180' : ''
              }`}
            />
          </div>
        </button>

        {onInspectActive && (
          <M3Tooltip label="Инспектор профиля и адаптация параметров">
            <button
              type="button"
              aria-label="Инспектор профиля"
              onClick={() => onInspectActive(activeServer.id)}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface-variant)] transition-colors hover:border-[var(--md-outline)] hover:text-[var(--md-on-surface)]"
            >
              <Sliders className="h-3.5 w-3.5" />
            </button>
          </M3Tooltip>
        )}

        <M3Tooltip label="Проверить TCP-пинг выбранного узла">
          <button
            type="button"
            aria-label="Проверить TCP-пинг"
            onClick={() => onPingActive(activeServer.id)}
            disabled={isPinging}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface-variant)] transition-colors hover:border-[var(--md-outline)] hover:text-[var(--md-on-surface)] disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isPinging ? 'animate-spin' : ''}`} />
          </button>
        </M3Tooltip>
      </div>

      <AnimatePresence>
        {open && profiles.length > 0 && (
          <motion.div
            role="listbox"
            initial={{ opacity: 0, y: 6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 6, scale: 0.98 }}
            transition={{ duration: 0.14 }}
            className="aura-scroll absolute bottom-full left-0 right-0 z-30 mb-2 max-h-64 overflow-y-auto rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-highest)] p-1.5 shadow-2xl"
          >
            {profiles.length > 6 && (
              <div className="sticky top-0 z-10 mb-1.5 bg-[var(--md-surface-container-highest)] pb-1">
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-[var(--md-on-surface-variant)]" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Быстрый поиск страны или узла..."
                    className="h-8 w-full rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] pr-7 pl-8 text-[0.75rem] text-[var(--md-on-surface)] placeholder:text-[var(--md-on-surface-variant)]/70 focus:border-[var(--md-primary)]"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      aria-label="Очистить поиск"
                      onClick={() => setSearchQuery('')}
                      className="absolute top-1/2 right-2 -translate-y-1/2 rounded-full p-0.5 text-[var(--md-on-surface-variant)] hover:text-[var(--md-on-surface)]"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  )}
                </div>
              </div>
            )}

            {profiles.length > 1 && !searchQuery.trim() && (
              <button
                type="button"
                disabled={isAutoSelecting}
                onClick={() => {
                  setOpen(false);
                  onAutoSelectFastest();
                }}
                className="mb-1 flex w-full items-center justify-between rounded-xl bg-[var(--md-primary-container)] px-3 py-1.5 text-[0.75rem] font-semibold text-[var(--md-on-primary-container)] transition-opacity hover:opacity-90"
              >
                <span className="flex items-center gap-2">
                  <Zap className="h-3.5 w-3.5" />
                  Выбрать самый быстрый сервер
                </span>
                <span className="text-[0.65rem] opacity-80">TCP автопинг</span>
              </button>
            )}

            {filteredProfiles.length === 0 ? (
              <div className="py-4 text-center text-[0.72rem] text-[var(--md-on-surface-variant)]">
                Ничего не найдено
              </div>
            ) : (
              filteredProfiles.map((srv) => {
                const selected = srv.id === activeServer.id;
                const dName = formatServerDisplayName(srv.name, srv.countryCode);
                const cName = getCountryName(srv.countryCode);
                const nCount = getProfileNodeCount(srv);
                const sub = [
                  shouldShowCountryInSubtitle(dName, cName) ? cName : null,
                  formatProtocolBadge(srv),
                  nCount > 1 ? formatNodePoolLabel(nCount) : null,
                ]
                  .filter((p): p is string => Boolean(p))
                  .join(' • ');

                return (
                  <button
                    key={srv.id}
                    type="button"
                    role="option"
                    aria-selected={selected}
                    onClick={() => {
                      setOpen(false);
                      if (!selected) onSelectServer(srv.id);
                    }}
                    className={`flex w-full items-center justify-between gap-2 rounded-xl px-2.5 py-2 text-left text-[0.78rem] transition-colors ${
                      selected
                        ? 'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)]'
                        : 'text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container)] hover:text-[var(--md-on-surface)]'
                    }`}
                  >
                    <div className="flex min-w-0 items-center gap-2.5">
                      <CountryBadge code={srv.countryCode} size="sm" />
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 truncate font-medium text-[var(--md-on-surface)]">
                          {srv.favorite && (
                            <Star className="h-3 w-3 shrink-0 fill-[var(--md-warning)] text-[var(--md-warning)]" />
                          )}
                          <M3Tooltip label={dName} className="min-w-0 max-w-full">
                            <span className="truncate block">{dName}</span>
                          </M3Tooltip>
                        </div>
                        <div className="text-[0.65rem] text-[var(--md-on-surface-variant)]">{sub}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[0.6875rem] text-[var(--md-on-surface-variant)] font-mono-num">
                        {srv.latencyMs ? `${srv.latencyMs} мс` : ''}
                      </span>
                      {selected && <Check className="h-3.5 w-3.5 text-[var(--md-primary)]" />}
                    </div>
                  </button>
                );
              })
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
