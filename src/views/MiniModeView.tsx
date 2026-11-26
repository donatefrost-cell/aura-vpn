import {
  ArrowDown,
  ArrowUp,
  Globe,
  Maximize2,
  ShieldAlert,
  Terminal,
  Zap,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { ConnectionDial } from '../components/ConnectionDial';
import { ServerQuickPick } from '../components/ServerQuickPick';
import { TrafficGraph } from '../components/TrafficGraph';
import {
  M3Button,
  M3Chip,
  M3SegmentedButton,
  M3StatusBadge,
  M3Tooltip,
} from '../components/md3';
import { useLiveTraffic } from '../stores/liveStore';
import type {
  AppSettings,
  ConnectionMode,
  ConnectionSnapshot,
  ServerProfile,
} from '../types/vpn';
import { formatDuration, formatSpeed, isRuBypassActive } from '../utils/format';

interface MiniModeViewProps {
  profiles: ServerProfile[];
  activeServer: ServerProfile | null;
  connection: ConnectionSnapshot;
  settings: AppSettings;
  isPingingActive: boolean;
  isAutoSelecting: boolean;
  onToggleConnect: () => void;
  onSelectServer: (id: string) => void;
  onPingActive: (id: string) => void;
  onAutoSelectFastest: () => void;
  onToggleMode: (mode: ConnectionMode) => void;
  onToggleRuDirect: () => void;
  onToggleKillSwitch: () => void;
  onOpenFullMode: () => void;
  onOpenDiagnostics: () => void;
}

export function MiniModeView({
  profiles,
  activeServer,
  connection,
  settings,
  isPingingActive,
  isAutoSelecting,
  onToggleConnect,
  onSelectServer,
  onPingActive,
  onAutoSelectFastest,
  onToggleMode,
  onToggleRuDirect,
  onToggleKillSwitch,
  onOpenFullMode,
  onOpenDiagnostics,
}: MiniModeViewProps) {
  const traffic = useLiveTraffic();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const ruDirectActive = isRuBypassActive(settings.routing);
  const isConnected = connection.status === 'connected';
  const isError = connection.status === 'error';
  const isBusy =
    connection.status === 'connecting' ||
    connection.status === 'verifying' ||
    connection.status === 'switching' ||
    connection.status === 'reconnecting' ||
    connection.status === 'disconnecting';

  useEffect(() => {
    if (!isConnected || !connection.connectedSince) return;
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [isConnected, connection.connectedSince]);

  const badgeTone = isConnected
    ? 'success'
    : connection.killSwitchEngaged
      ? 'warning'
      : isError
        ? 'error'
        : isBusy
          ? 'primary'
          : 'neutral';

  const statusText = isConnected
    ? 'Защита активна'
    : connection.killSwitchEngaged
      ? 'Kill Switch активен'
      : isError
        ? connection.errorInfo?.title ?? 'Ошибка'
        : isBusy
          ? 'Подключение...'
          : 'Отключено';

  return (
    <div
      data-testid="mini-mode-view"
      className="aura-scroll flex h-full flex-col justify-between gap-1.5 overflow-y-auto px-3 py-2"
    >
      <div className="flex items-center justify-between gap-2">
        <M3StatusBadge tone={badgeTone}>
          <span>{statusText}</span>
          {isConnected && connection.connectedSince && (
            <span className="font-mono-num opacity-85">
              {formatDuration(connection.connectedSince, nowMs)}
            </span>
          )}
        </M3StatusBadge>

        <span className="text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)]">
          {settings.connectionMode === 'tun' ? 'TUN' : 'Прокси'}
          {ruDirectActive ? ' • РФ' : ''}
        </span>
      </div>

      <div className="flex flex-col items-center justify-center gap-1">
        <ConnectionDial
          status={connection.status}
          disabled={!activeServer}
          compact
          onToggle={onToggleConnect}
        />

        {isError && connection.errorMessage && (
          <div
            title={connection.errorMessage}
            className="w-full line-clamp-2 rounded-xl bg-[var(--md-error-container)] px-2.5 py-1 text-center text-[0.6875rem] font-medium text-[var(--md-error)]"
          >
            {connection.errorMessage}
          </div>
        )}
        {connection.killSwitchEngaged && (
          <button
            type="button"
            onClick={onToggleKillSwitch}
            className="w-full rounded-xl bg-[var(--md-error-container)] px-2.5 py-1 text-[0.6875rem] font-semibold text-[var(--md-error)] hover:brightness-105"
          >
            Kill Switch активен — нажмите для снятия
          </button>
        )}
      </div>

      <ServerQuickPick
        profiles={profiles}
        activeServer={activeServer}
        isBusy={isBusy}
        onSelectServer={onSelectServer}
        onPingActive={onPingActive}
        onAutoSelectFastest={onAutoSelectFastest}
        isPinging={isPingingActive}
        isAutoSelecting={isAutoSelecting}
      />

      <div className="space-y-1">
        <M3SegmentedButton
          size="sm"
          fullWidth
          value={settings.connectionMode}
          onChange={onToggleMode}
          options={[
            { id: 'system_proxy', label: 'Прокси' },
            { id: 'tun', label: 'TUN (весь ПК)' },
          ]}
        />

        <div className="grid grid-cols-3 gap-1.5">
          <M3Chip
            active={ruDirectActive}
            onClick={onToggleRuDirect}
            tooltip="Открывать российские сервисы и .ru напрямую"
            leading={<Globe className="h-3 w-3 shrink-0" />}
            className="w-full justify-center"
          >
            РФ
          </M3Chip>

          <M3Chip
            active={(settings.killSwitch?.mode ?? 'off') !== 'off' || settings.killSwitchEnabled}
            onClick={onToggleKillSwitch}
            tooltip="Блокировать трафик при обрыве VPN (Kill Switch)"
            leading={<ShieldAlert className="h-3 w-3 shrink-0" />}
            className="w-full justify-center"
          >
            Kill Switch
          </M3Chip>

          <M3Chip
            variant="assist"
            onClick={onAutoSelectFastest}
            tooltip="Выбрать самый быстрый сервер по TCP"
            leading={<Zap className="h-3 w-3 shrink-0 text-[var(--md-primary)]" />}
            className="w-full justify-center"
          >
            Быстрый
          </M3Chip>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-1.5">
        <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-2.5 py-1">
          <div className="flex items-center gap-1 text-[0.625rem] text-[var(--md-on-surface-variant)]">
            <ArrowDown className="h-3 w-3 text-[var(--md-success)]" />
            Загрузка
          </div>
          <div className="text-[0.8125rem] font-bold text-[var(--md-on-surface)] font-mono-num">
            {isConnected ? formatSpeed(traffic.rxBytesPerSec) : '—'}
          </div>
        </div>
        <div className="rounded-xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-2.5 py-1">
          <div className="flex items-center gap-1 text-[0.625rem] text-[var(--md-on-surface-variant)]">
            <ArrowUp className="h-3 w-3 text-[var(--md-primary)]" />
            Отдача
          </div>
          <div className="text-[0.8125rem] font-bold text-[var(--md-on-surface)] font-mono-num">
            {isConnected ? formatSpeed(traffic.txBytesPerSec) : '—'}
          </div>
        </div>
      </div>

      <TrafficGraph status={connection.status} compact />

      <div className="flex items-center justify-between">
        <M3Tooltip label="Открыть журнал и диагностику">
          <M3Button
            variant="text"
            size="sm"
            leadingIcon={<Terminal className="h-3.5 w-3.5" />}
            onClick={onOpenDiagnostics}
          >
            Логи
          </M3Button>
        </M3Tooltip>

        <M3Button
          variant="tonal"
          size="sm"
          leadingIcon={<Maximize2 className="h-3.5 w-3.5" />}
          onClick={onOpenFullMode}
        >
          Полный экран
        </M3Button>
      </div>
    </div>
  );
}
