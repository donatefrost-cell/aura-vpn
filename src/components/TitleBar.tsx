import {
  Laptop,
  Maximize2,
  Minimize2,
  Minus,
  Moon,
  Pin,
  PinOff,
  Search,
  ShieldAlert,
  Sun,
  Terminal,
  X,
} from 'lucide-react';
import { BRAND } from '../config/brand';
import type { AppNotification, ConnectionMode, ConnectionStatus, ThemeMode } from '../types/vpn';
import { AuraLogo } from './AuraLogo';
import { NotificationCenter } from './NotificationCenter';
import { M3Tooltip } from './md3';

interface TitleBarProps {
  theme: ThemeMode;
  status: ConnectionStatus;
  mode: ConnectionMode;
  ruDirectActive: boolean;
  killSwitchEnabled: boolean;
  killSwitchEngaged: boolean;
  miniMode: boolean;
  alwaysOnTop: boolean;
  onCycleTheme: () => void;
  onOpenDiagnostics: () => void;
  onOpenCommandPalette: () => void;
  onToggleMiniMode: () => void;
  onToggleAlwaysOnTop: () => void;
  onNavigateNotification: (link: NonNullable<AppNotification['deepLink']>) => void;
  onMinimize: () => void;
  onClose: () => void;
}

export function TitleBar({
  theme,
  status,
  mode,
  ruDirectActive,
  killSwitchEnabled,
  killSwitchEngaged,
  miniMode,
  alwaysOnTop,
  onCycleTheme,
  onOpenDiagnostics,
  onOpenCommandPalette,
  onToggleMiniMode,
  onToggleAlwaysOnTop,
  onNavigateNotification,
  onMinimize,
  onClose,
}: TitleBarProps) {
  const statusDotColor =
    status === 'connected'
      ? 'bg-[var(--md-success)]'
      : status === 'connecting' ||
          status === 'verifying' ||
          status === 'switching' ||
          status === 'reconnecting' ||
          status === 'disconnecting'
        ? 'bg-[var(--md-primary)] animate-pulse'
        : status === 'error'
          ? 'bg-[var(--md-error)]'
          : 'bg-[var(--md-on-surface-variant)]';

  const modeLabel = mode === 'tun' ? 'TUN • Весь ПК' : BRAND.modeLabel;
  const themeTitle =
    theme === 'dark'
      ? 'Тема: Тёмная (нажмите для Светлой)'
      : theme === 'light'
        ? 'Тема: Светлая (нажмите для Системной)'
        : 'Тема: Системная Windows (нажмите для Тёмной)';

  return (
    <header className="h-9.5 shrink-0 flex items-center justify-between border-b border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] pl-3 pr-1 transition-colors duration-150">
      <div
        data-tauri-drag-region
        className="flex flex-1 items-center gap-2 min-w-0 h-full pr-2 cursor-default"
      >
        <AuraLogo variant="mark" className="h-5 w-5 shrink-0 pointer-events-none" />
        <span className="font-display text-[0.8125rem] font-bold tracking-tight text-[var(--md-on-surface)] truncate pointer-events-none">
          {miniMode ? BRAND.shortName : BRAND.appName}
        </span>

        {miniMode ? (
          <span className={`h-2 w-2 rounded-full shrink-0 pointer-events-none ${statusDotColor}`} />
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-[var(--md-surface-container-high)] px-2.5 py-0.5 text-[0.65rem] font-medium text-[var(--md-on-surface-variant)] shrink-0 pointer-events-none">
              <span className={`h-1.5 w-1.5 rounded-full ${statusDotColor}`} />
              {modeLabel}
            </span>

            {ruDirectActive && (
              <span className="hidden lg:inline-flex items-center rounded-full bg-[var(--md-secondary-container)] px-2 py-0.5 text-[0.65rem] font-medium text-[var(--md-on-secondary-container)] shrink-0 pointer-events-none">
                РФ напрямую
              </span>
            )}

            {(killSwitchEnabled || killSwitchEngaged) && (
              <span
                className={`hidden md:inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.65rem] font-medium shrink-0 pointer-events-none ${
                  killSwitchEngaged
                    ? 'bg-[var(--md-error-container)] text-[var(--md-error)]'
                    : 'bg-[var(--md-surface-container-high)] text-[var(--md-on-surface-variant)]'
                }`}
              >
                <ShieldAlert className="h-2.5 w-2.5" />
                Kill Switch
              </span>
            )}
          </>
        )}
      </div>

      <div className="flex items-center gap-0.5 shrink-0">
        {!miniMode && (
          <M3Tooltip label="Палитра команд и быстрый поиск" shortcut="Ctrl+K">
            <button
              type="button"
              onClick={onOpenCommandPalette}
              data-testid="command-palette-trigger"
              className="hidden sm:flex h-7 items-center gap-1.5 rounded-lg border border-[var(--md-outline-variant)] bg-[var(--md-surface-container)] px-2 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)] transition-colors hover:border-[var(--md-outline)] hover:text-[var(--md-on-surface)]"
            >
              <Search className="h-3 w-3" />
              <span className="hidden md:inline">Поиск</span>
              <kbd className="hidden lg:inline rounded bg-[var(--md-surface-container-highest)] px-1 font-mono text-[0.58rem]">
                Ctrl+K
              </kbd>
            </button>
          </M3Tooltip>
        )}

        {miniMode && (
          <M3Tooltip label={alwaysOnTop ? 'Открепить окно' : 'Закрепить поверх окон'}>
            <button
              type="button"
              onClick={onToggleAlwaysOnTop}
              aria-label={alwaysOnTop ? 'Открепить окно' : 'Закрепить поверх окон'}
              className={`flex h-7 w-7 items-center justify-center rounded-lg transition-colors ${
                alwaysOnTop
                  ? 'bg-[var(--md-primary-container)] text-[var(--md-on-primary-container)]'
                  : 'text-[var(--md-on-surface-variant)] hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]'
              }`}
            >
              {alwaysOnTop ? <Pin className="h-3.5 w-3.5" /> : <PinOff className="h-3.5 w-3.5" />}
            </button>
          </M3Tooltip>
        )}

        <NotificationCenter onNavigate={onNavigateNotification} />

        {!miniMode && (
          <M3Tooltip label="Диагностика и журнал работы">
            <button
              type="button"
              onClick={onOpenDiagnostics}
              className="flex h-7 items-center gap-1.5 rounded-lg px-2 text-[0.7rem] font-medium text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]"
            >
              <Terminal className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Логи</span>
            </button>
          </M3Tooltip>
        )}

        <M3Tooltip
          label={miniMode ? 'Развернуть полный интерфейс' : 'Компактный мини-режим (380×540)'}
          shortcut="Ctrl+Shift+M"
        >
          <button
            type="button"
            onClick={onToggleMiniMode}
            data-testid="mini-mode-toggle"
            aria-label={miniMode ? 'Развернуть полный интерфейс' : 'Компактный мини-режим'}
            className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]"
          >
            {miniMode ? <Maximize2 className="h-3.5 w-3.5" /> : <Minimize2 className="h-3.5 w-3.5" />}
          </button>
        </M3Tooltip>

        {!miniMode && (
          <M3Tooltip label={themeTitle}>
            <button
              type="button"
              onClick={onCycleTheme}
              aria-label={themeTitle}
              className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]"
            >
              {theme === 'dark' ? (
                <Moon className="h-3.5 w-3.5" />
              ) : theme === 'light' ? (
                <Sun className="h-3.5 w-3.5" />
              ) : (
                <Laptop className="h-3.5 w-3.5" />
              )}
            </button>
          </M3Tooltip>
        )}

        <div className="mx-0.5 h-3.5 w-px bg-[var(--md-outline-variant)]" />

        <M3Tooltip label="Свернуть окно">
          <button
            type="button"
            onClick={onMinimize}
            aria-label="Свернуть окно"
            className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-surface-container-high)] hover:text-[var(--md-on-surface)]"
          >
            <Minus className="h-3.5 w-3.5" />
          </button>
        </M3Tooltip>

        <M3Tooltip label="Закрыть окно">
          <button
            type="button"
            onClick={onClose}
            aria-label="Закрыть окно"
            className="flex h-7 w-7 items-center justify-center rounded-lg text-[var(--md-on-surface-variant)] transition-colors hover:bg-[var(--md-error-container)] hover:text-[var(--md-error)]"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </M3Tooltip>
      </div>
    </header>
  );
}
