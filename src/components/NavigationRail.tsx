import {
  ClipboardPaste,
  GitFork,
  Home,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Radio,
  Rss,
  Settings,
} from 'lucide-react';
import { motion } from 'motion/react';
import { BRAND } from '../config/brand';
import type { CoreDiagnostics, NavTab } from '../types/vpn';
import { M3Tooltip } from './md3';

interface NavigationRailProps {
  activeTab: NavTab;
  expanded: boolean;
  serverCount: number;
  subscriptionCount: number;
  activeRoutingCount: number;
  diagnostics: CoreDiagnostics;
  onSelectTab: (tab: NavTab) => void;
  onToggleExpanded: () => void;
  onOpenImport: () => void;
  onPasteClipboard: () => void;
  onOpenDiagnostics: () => void;
}

export function NavigationRail({
  activeTab,
  expanded,
  serverCount,
  subscriptionCount,
  activeRoutingCount,
  diagnostics,
  onSelectTab,
  onToggleExpanded,
  onOpenImport,
  onPasteClipboard,
  onOpenDiagnostics,
}: NavigationRailProps) {
  const navItems: Array<{
    id: NavTab;
    label: string;
    shortcut: string;
    icon: typeof Home;
    badge?: number;
  }> = [
    { id: 'home', label: 'Главная', shortcut: 'Alt+1', icon: Home },
    { id: 'servers', label: 'Серверы', shortcut: 'Alt+2', icon: Radio, badge: serverCount },
    { id: 'subscriptions', label: 'Подписки', shortcut: 'Alt+3', icon: Rss, badge: subscriptionCount },
    { id: 'routing', label: 'Маршруты', shortcut: 'Alt+4', icon: GitFork, badge: activeRoutingCount },
    { id: 'settings', label: 'Настройки', shortcut: 'Alt+5', icon: Settings },
  ];

  const coreVer = diagnostics.coreVersion.match(/\d+\.\d+\.\d+/)?.[0] ?? 'v26';

  return (
    <aside
      className={`shrink-0 flex flex-col justify-between border-r border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] transition-[width] duration-200 ease-out ${
        expanded ? 'w-[13rem] p-2.5' : 'w-[4.875rem] px-2 py-2.5'
      }`}
    >
      <div className="space-y-3">
        {/* Rail / Drawer toggle + MD3 Tonal FAB actions */}
        <div className={`flex flex-col gap-2 ${expanded ? '' : 'items-center'}`}>
          <M3Tooltip label={expanded ? 'Свернуть панель' : 'Развернуть панель'} side="right">
            <button
              type="button"
              onClick={onToggleExpanded}
              aria-label={expanded ? 'Свернуть панель' : 'Развернуть панель'}
              className={`flex h-8 items-center rounded-xl text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)] ${
                expanded ? 'w-full justify-between px-2.5' : 'w-11 justify-center'
              }`}
            >
              {expanded && (
                <span className="text-[0.6875rem] font-semibold uppercase tracking-[0.07em] text-[var(--md-on-surface-variant)]">
                  Меню
                </span>
              )}
              {expanded ? (
                <PanelLeftClose className="h-4 w-4" />
              ) : (
                <PanelLeftOpen className="h-4 w-4" />
              )}
            </button>
          </M3Tooltip>

          <M3Tooltip label="Добавить VPN-ключ, конфиг или подписку" side="right" disabled={expanded}>
            <button
              type="button"
              onClick={onOpenImport}
              aria-label="Добавить ключ"
              className={`flex items-center justify-center rounded-2xl bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)] font-semibold transition-all hover:brightness-105 active:scale-[0.97] ${
                expanded ? 'h-10 w-full gap-2 px-3 text-[0.78125rem]' : 'h-11 w-11'
              }`}
            >
              <Plus className="h-4.5 w-4.5 shrink-0" />
              {expanded && <span className="truncate">Добавить ключ</span>}
            </button>
          </M3Tooltip>

          <M3Tooltip label="Импортировать из буфера обмена" side="right" disabled={expanded}>
            <button
              type="button"
              onClick={onPasteClipboard}
              aria-label="Импорт из буфера"
              className={`flex items-center justify-center rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] text-[var(--md-on-surface-variant)] transition-colors hover:border-[var(--md-outline)] hover:text-[var(--md-on-surface)] ${
                expanded ? 'h-8 w-full gap-2 px-3 text-[0.75rem] font-medium' : 'h-8 w-11'
              }`}
            >
              <ClipboardPaste className="h-3.5 w-3.5 shrink-0" />
              {expanded && <span className="truncate">Из буфера</span>}
            </button>
          </M3Tooltip>
        </div>

        {/* Navigation Destinations */}
        <nav aria-label="Основная навигация" className="space-y-1 pt-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <M3Tooltip key={item.id} label={item.label} shortcut={item.shortcut} side="right">
                <button
                  type="button"
                  aria-current={active ? 'page' : undefined}
                  onClick={() => onSelectTab(item.id)}
                  className={`group relative flex w-full items-center transition-colors ${
                    expanded
                      ? 'h-9.5 justify-between rounded-2xl px-3'
                      : 'flex-col justify-center gap-0.5 rounded-2xl py-1.5'
                  }`}
                >
                {expanded ? (
                  <>
                    {active && (
                      <motion.span
                        layoutId="nav-rail-pill"
                        transition={{ type: 'spring', stiffness: 460, damping: 36 }}
                        className="absolute inset-0 rounded-2xl bg-[var(--md-secondary-container)]"
                      />
                    )}
                    <span
                      className={`relative z-10 flex items-center gap-2.5 text-[0.78rem] font-medium ${
                        active
                          ? 'text-[var(--md-on-secondary-container)]'
                          : 'text-[var(--md-on-surface-variant)] group-hover:text-[var(--md-on-surface)]'
                      }`}
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span>{item.label}</span>
                    </span>
                    {item.badge !== undefined && item.badge > 0 && (
                      <span
                        className={`relative z-10 rounded-full px-1.5 py-0.5 text-[0.65rem] font-semibold font-mono-num ${
                          active
                            ? 'bg-[var(--md-primary)]/18 text-[var(--md-on-secondary-container)]'
                            : 'bg-[var(--md-surface-container-highest)] text-[var(--md-on-surface-variant)]'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </>
                ) : (
                  <>
                    <span className="relative flex h-7 w-12 items-center justify-center rounded-full">
                      {active && (
                        <motion.span
                          layoutId="nav-rail-pill"
                          transition={{ type: 'spring', stiffness: 460, damping: 36 }}
                          className="absolute inset-0 rounded-full bg-[var(--md-secondary-container)]"
                        />
                      )}
                      <Icon
                        className={`relative z-10 h-4 w-4 transition-colors ${
                          active
                            ? 'text-[var(--md-on-secondary-container)]'
                            : 'text-[var(--md-on-surface-variant)] group-hover:text-[var(--md-on-surface)]'
                        }`}
                      />
                      {item.badge !== undefined && item.badge > 0 && (
                        <span className="absolute -top-1 right-0 z-10 min-w-[16px] rounded-full bg-[var(--md-primary)] px-1 text-center text-[0.58rem] font-bold leading-[15px] text-[var(--md-on-primary)] font-mono-num shadow-xs">
                          {item.badge > 99 ? '99+' : item.badge}
                        </span>
                      )}
                    </span>
                    <span
                      className={`text-[0.65rem] leading-tight font-medium truncate max-w-full ${
                        active
                          ? 'text-[var(--md-on-surface)]'
                          : 'text-[var(--md-on-surface-variant)]'
                      }`}
                    >
                      {item.label}
                    </span>
                  </>
                )}
              </button>
              </M3Tooltip>
            );
          })}
        </nav>
      </div>

      {/* Bottom Core Status Pill */}
      <M3Tooltip
        label={`Диагностика ядра • ${BRAND.coreName} ${coreVer} • v${BRAND.version}`}
        side="right"
      >
        <button
          type="button"
          onClick={onOpenDiagnostics}
          className={`flex items-center rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] transition-colors hover:border-[var(--md-outline)] hover:bg-[var(--md-surface-container-high)] ${
            expanded ? 'w-full justify-between px-2.5 py-2 text-left' : 'w-full flex-col gap-0.5 py-2'
          }`}
        >
          {expanded ? (
            <>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-[0.6875rem] font-semibold text-[var(--md-on-surface)]">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      diagnostics.coreAvailable
                        ? 'bg-[var(--md-success)]'
                        : 'bg-[var(--md-error)]'
                    }`}
                  />
                  {BRAND.coreName}
                </div>
                <div className="truncate text-[0.625rem] text-[var(--md-on-surface-variant)] font-mono-num">
                  {diagnostics.coreAvailable
                    ? `${coreVer} • ${diagnostics.wintunAvailable ? 'TUN готов' : 'Proxy'}`
                    : 'Ядро не найдено'}
                </div>
              </div>
              <span className="text-[0.625rem] font-medium text-[var(--md-on-surface-variant)] font-mono-num">
                v{BRAND.version}
              </span>
            </>
          ) : (
            <>
              <span className="flex items-center gap-1 text-[0.625rem] font-semibold text-[var(--md-on-surface)]">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    diagnostics.coreAvailable ? 'bg-[var(--md-success)]' : 'bg-[var(--md-error)]'
                  }`}
                />
                <span>Core</span>
              </span>
              <span className="text-[0.59375rem] text-[var(--md-on-surface-variant)] font-mono-num">
                v{BRAND.version}
              </span>
            </>
          )}
        </button>
      </M3Tooltip>
    </aside>
  );
}
