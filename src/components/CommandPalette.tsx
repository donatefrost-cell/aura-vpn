import {
  Activity,
  CornerDownLeft,
  GitFork,
  Home,
  Minimize2,
  Moon,
  Power,
  Radio,
  RefreshCw,
  Rss,
  Search,
  Settings,
  Shield,
  Sliders,
  Zap,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type {
  BehaviorProfile,
  ConnectionStatus,
  NavTab,
  ServerProfile,
  Subscription,
} from '../types/vpn';
import { formatProtocolBadge, formatServerDisplayName, getCountryName } from '../utils/format';
import { CountryBadge } from './CountryBadge';

export interface PaletteItem {
  id: string;
  group: 'Действия' | 'Профили поведения' | 'Разделы' | 'Подписки' | 'Серверы';
  label: string;
  subtitle?: string;
  keywords: string;
  shortcut?: string;
  icon: ReactNode;
  onExecute: () => void;
  onSecondaryExecute?: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  status: ConnectionStatus;
  profiles: ServerProfile[];
  subscriptions: Subscription[];
  behaviorProfiles: BehaviorProfile[];
  onToggleConnect: () => void;
  onAutoSelectFastest: () => void;
  onRefreshAllSubs: () => void;
  onOpenDiagnostics: () => void;
  onCycleTheme: () => void;
  onToggleMiniMode: () => void;
  onSelectTab: (tab: NavTab, settingsSection?: string) => void;
  onSelectServer: (id: string) => void;
  onConnectServer: (id: string) => void;
  onApplyBehaviorProfile: (id: BehaviorProfile['id']) => void;
}

export function CommandPalette({
  open,
  onClose,
  status,
  profiles,
  subscriptions,
  behaviorProfiles,
  onToggleConnect,
  onAutoSelectFastest,
  onRefreshAllSubs,
  onOpenDiagnostics,
  onCycleTheme,
  onToggleMiniMode,
  onSelectTab,
  onSelectServer,
  onConnectServer,
  onApplyBehaviorProfile,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      setQuery('');
      setActiveIdx(0);
      return;
    }
    window.setTimeout(() => inputRef.current?.focus(), 20);
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const isConnected = status === 'connected';
    const actions: PaletteItem[] = [
      {
        id: 'act-toggle-vpn',
        group: 'Действия',
        label: isConnected ? 'Отключить VPN' : 'Подключить VPN',
        subtitle: isConnected ? 'Остановить текущую сессию' : 'Запустить туннель на активном узле',
        keywords: 'connect disconnect vpn подключить отключить старт стоп',
        icon: <Power className="h-4 w-4 text-[var(--md-primary)]" />,
        onExecute: onToggleConnect,
      },
      {
        id: 'act-autoping',
        group: 'Действия',
        label: 'Автовыбор быстрого сервера',
        subtitle: 'Проверить задержку и выбрать минимальный TCP пинг',
        keywords: 'autoping ping fastest latency автопинг пинг задержка быстрый',
        icon: <Zap className="h-4 w-4 text-[var(--md-success)]" />,
        onExecute: onAutoSelectFastest,
      },
      {
        id: 'act-refresh-subs',
        group: 'Действия',
        label: 'Обновить все подписки',
        subtitle: `Подписок: ${subscriptions.length}`,
        keywords: 'refresh subscriptions update подписки обновить',
        icon: <RefreshCw className="h-4 w-4 text-[var(--md-on-surface-variant)]" />,
        onExecute: onRefreshAllSubs,
      },
      {
        id: 'act-diagnostics',
        group: 'Действия',
        label: 'Открыть диагностику и логи',
        subtitle: 'Журнал работы ядра и состояние компонентов',
        keywords: 'diagnostics logs journal диагностика логи',
        icon: <Activity className="h-4 w-4 text-[var(--md-on-surface-variant)]" />,
        onExecute: onOpenDiagnostics,
      },
      {
        id: 'act-theme',
        group: 'Действия',
        label: 'Переключить тему оформления',
        subtitle: 'Тёмная / Светлая / Системная Windows',
        keywords: 'theme dark light system тема светлая тёмная',
        icon: <Moon className="h-4 w-4 text-[var(--md-on-surface-variant)]" />,
        onExecute: onCycleTheme,
      },
      {
        id: 'act-mini',
        group: 'Действия',
        label: 'Мини-режим окна (380×540)',
        subtitle: 'Переключить компактный вид приложения',
        keywords: 'mini compact window мини режим компактное окно',
        shortcut: 'Ctrl+Shift+M',
        icon: <Minimize2 className="h-4 w-4 text-[var(--md-on-surface-variant)]" />,
        onExecute: onToggleMiniMode,
      },
    ];

    const nav: PaletteItem[] = [
      {
        id: 'nav-home',
        group: 'Разделы',
        label: 'Главная',
        keywords: 'home main главная статус график',
        shortcut: 'Alt+1',
        icon: <Home className="h-4 w-4" />,
        onExecute: () => onSelectTab('home'),
      },
      {
        id: 'nav-servers',
        group: 'Разделы',
        label: 'Серверы',
        subtitle: `Всего узлов: ${profiles.length}`,
        keywords: 'servers nodes countries серверы узлы страны',
        shortcut: 'Alt+2',
        icon: <Radio className="h-4 w-4" />,
        onExecute: () => onSelectTab('servers'),
      },
      {
        id: 'nav-subs',
        group: 'Разделы',
        label: 'Подписки',
        keywords: 'subscriptions links подписки ссылки',
        shortcut: 'Alt+3',
        icon: <Rss className="h-4 w-4" />,
        onExecute: () => onSelectTab('subscriptions'),
      },
      {
        id: 'nav-routing',
        group: 'Разделы',
        label: 'Маршрутизация и Split Tunneling',
        keywords: 'routing split tunnel rules маршруты правила рф',
        shortcut: 'Alt+4',
        icon: <GitFork className="h-4 w-4" />,
        onExecute: () => onSelectTab('routing'),
      },
      {
        id: 'nav-settings',
        group: 'Разделы',
        label: 'Настройки',
        keywords: 'settings config настройки параметры',
        shortcut: 'Alt+5',
        icon: <Settings className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings'),
      },
      {
        id: 'nav-settings-security',
        group: 'Разделы',
        label: 'Настройки → Kill Switch и Центр защиты',
        keywords: 'kill switch security wfp firewall защита безопасность',
        icon: <Shield className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'kill-switch'),
      },
      {
        id: 'nav-settings-core',
        group: 'Разделы',
        label: 'Настройки → Ядра (Xray-core / AWG / Wintun)',
        keywords: 'core xray wireproxy wintun sha256 ядро',
        icon: <Sliders className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'vpn-core'),
      },
      {
        id: 'nav-settings-dns',
        group: 'Разделы',
        label: 'Настройки → DNS-менеджер и DoH/DoT',
        keywords: 'dns doh dot резолвер утечка',
        icon: <Sliders className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'dns-manager'),
      },
      {
        id: 'nav-settings-tun',
        group: 'Разделы',
        label: 'Настройки → TUN и виртуальные адаптеры',
        keywords: 'tun wintun adapter mtu адаптер',
        icon: <Sliders className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'tun-adapters'),
      },
      {
        id: 'nav-settings-doctor',
        group: 'Разделы',
        label: 'Настройки → Сетевой доктор (12 проверок)',
        keywords: 'network doctor diagnostics check диагностика сети проверка',
        icon: <Activity className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'network-doctor'),
      },
      {
        id: 'nav-settings-privacy',
        group: 'Разделы',
        label: 'Настройки → Приватность, DPAPI и очистка',
        keywords: 'history privacy hwid purge история приватность',
        icon: <Sliders className="h-4 w-4" />,
        onExecute: () => onSelectTab('settings', 'privacy-telemetry'),
      },
    ];

    const profItems: PaletteItem[] = behaviorProfiles.map((bp) => ({
      id: `bp-${bp.id}`,
      group: 'Профили поведения',
      label: `Профиль: ${bp.name}`,
      subtitle: bp.description,
      keywords: `profile behavior ${bp.id} ${bp.name} профиль`,
      icon: <Sliders className="h-4 w-4 text-[var(--md-tertiary)]" />,
      onExecute: () => onApplyBehaviorProfile(bp.id),
    }));

    const subItems: PaletteItem[] = subscriptions.map((sub) => ({
      id: `sub-${sub.id}`,
      group: 'Подписки',
      label: sub.title,
      subtitle: `Узлов: ${sub.serverCount}`,
      keywords: `subscription ${sub.title} подписка`,
      icon: <Rss className="h-4 w-4" />,
      onExecute: () => onSelectTab('subscriptions'),
    }));

    const srvItems: PaletteItem[] = profiles.map((srv) => {
      const cname = getCountryName(srv.countryCode) ?? '';
      const dName = formatServerDisplayName(srv.name, srv.countryCode);
      return {
        id: `srv-${srv.id}`,
        group: 'Серверы',
        label: dName,
        subtitle: `${cname ? `${cname} • ` : ''}${formatProtocolBadge(srv)}${srv.latencyMs ? ` • ${srv.latencyMs} мс` : ''}`,
        keywords: `${dName} ${srv.name} ${cname} ${srv.countryCode ?? ''} ${srv.protocol} ${srv.address}`,
        icon: <CountryBadge code={srv.countryCode} size="sm" />,
        onExecute: () => onSelectServer(srv.id),
        onSecondaryExecute: () => onConnectServer(srv.id),
      };
    });

    return [...actions, ...profItems, ...nav, ...subItems, ...srvItems];
  }, [
    behaviorProfiles,
    onApplyBehaviorProfile,
    onAutoSelectFastest,
    onConnectServer,
    onCycleTheme,
    onOpenDiagnostics,
    onRefreshAllSubs,
    onSelectServer,
    onSelectTab,
    onToggleConnect,
    onToggleMiniMode,
    profiles,
    status,
    subscriptions,
  ]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items.slice(0, 22);
    const terms = q.split(/\s+/).filter(Boolean);
    return items
      .filter((item) => {
        const hay = `${item.label} ${item.subtitle ?? ''} ${item.keywords}`.toLowerCase();
        return terms.every((t) => hay.includes(t));
      })
      .slice(0, 40);
  }, [items, query]);

  useEffect(() => {
    setActiveIdx((prev) => (filtered.length === 0 ? 0 : Math.min(prev, filtered.length - 1)));
  }, [filtered.length]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((prev) => (filtered.length > 0 ? (prev + 1) % filtered.length : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((prev) =>
          filtered.length > 0 ? (prev - 1 + filtered.length) % filtered.length : 0,
        );
      } else if (e.key === 'Enter') {
        const current = filtered[activeIdx];
        if (!current) return;
        e.preventDefault();
        onClose();
        if (e.shiftKey && current.onSecondaryExecute) {
          current.onSecondaryExecute();
        } else {
          current.onExecute();
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [activeIdx, filtered, onClose, open]);

  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-palette-idx="${activeIdx}"]`);
    if (el instanceof HTMLElement && typeof el.scrollIntoView === 'function') {
      el.scrollIntoView({ block: 'nearest' });
    }
  }, [activeIdx]);

  const grouped = useMemo(() => {
    const map = new Map<PaletteItem['group'], Array<{ item: PaletteItem; flatIdx: number }>>();
    filtered.forEach((item, flatIdx) => {
      const list = map.get(item.group) ?? [];
      list.push({ item, flatIdx });
      map.set(item.group, list);
    });
    return Array.from(map.entries());
  }, [filtered]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.14 }}
          onClick={onClose}
          className="fixed inset-0 z-[85] flex items-start justify-center bg-black/55 px-4 pt-16 backdrop-blur-xs"
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-label="Палитра команд AURA VPN"
            data-testid="command-palette"
            initial={{ opacity: 0, scale: 0.96, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -8 }}
            transition={{ duration: 0.16, ease: 'easeOut' }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-[540px] overflow-hidden rounded-3xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-high)] shadow-2xl"
          >
            <div className="flex items-center gap-2.5 border-b border-[var(--md-outline-variant)] px-4 py-3">
              <Search className="h-4 w-4 shrink-0 text-[var(--md-primary)]" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setActiveIdx(0);
                }}
                placeholder="Поиск серверов, стран, команд и настроек (Ctrl+K)..."
                className="w-full bg-transparent text-[0.875rem] text-[var(--md-on-surface)] placeholder:text-[var(--md-on-surface-variant)]/75 focus:outline-none"
              />
              <kbd className="rounded-lg bg-[var(--md-surface-container)] px-1.5 py-0.5 font-mono text-[0.65rem] text-[var(--md-on-surface-variant)]">
                Esc
              </kbd>
            </div>

            <div ref={listRef} className="aura-scroll max-h-[360px] overflow-y-auto p-2 space-y-2.5">
              {grouped.length === 0 ? (
                <div className="py-10 text-center text-[0.78rem] text-[var(--md-on-surface-variant)]">
                  По вашему запросу ничего не найдено
                </div>
              ) : (
                grouped.map(([group, rows]) => (
                  <div key={group}>
                    <div className="px-2.5 pb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-[var(--md-on-surface-variant)]">
                      {group}
                    </div>
                    <div className="space-y-0.5">
                      {rows.map(({ item, flatIdx }) => {
                        const isSelected = flatIdx === activeIdx;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            data-palette-idx={flatIdx}
                            onMouseEnter={() => setActiveIdx(flatIdx)}
                            onClick={() => {
                              onClose();
                              item.onExecute();
                            }}
                            className={`flex w-full items-center justify-between gap-3 rounded-2xl px-3 py-2 text-left transition-colors ${
                              isSelected
                                ? 'bg-[var(--md-secondary-container)] text-[var(--md-on-secondary-container)]'
                                : 'text-[var(--md-on-surface)] hover:bg-[var(--md-surface-container)]'
                            }`}
                          >
                            <div className="flex min-w-0 items-center gap-2.5">
                              <span className="shrink-0">{item.icon}</span>
                              <div className="min-w-0">
                                <div className="truncate text-[0.8125rem] font-medium">
                                  {item.label}
                                </div>
                                {item.subtitle && (
                                  <div className="truncate text-[0.6875rem] opacity-75">
                                    {item.subtitle}
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="flex shrink-0 items-center gap-1.5">
                              {item.shortcut && (
                                <kbd className="rounded bg-[var(--md-surface-container)] px-1.5 py-0.5 font-mono text-[0.625rem] text-[var(--md-on-surface-variant)]">
                                  {item.shortcut}
                                </kbd>
                              )}
                              {isSelected && <CornerDownLeft className="h-3.5 w-3.5 opacity-75" />}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="flex items-center justify-between border-t border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-4 py-1.5 text-[0.65rem] text-[var(--md-on-surface-variant)]">
              <span>↑↓ выбор • Enter выполнить</span>
              <span>Shift+Enter на сервере — подключиться сразу</span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
