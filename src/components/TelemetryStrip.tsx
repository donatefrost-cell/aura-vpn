import { ArrowDown, ArrowUp, Globe2, HardDriveDownload, Shield } from 'lucide-react';
import { useLiveTraffic } from '../stores/liveStore';
import type { ConnectionSnapshot } from '../types/vpn';
import { formatBytes, formatSpeed } from '../utils/format';

interface TelemetryStripProps {
  connection: ConnectionSnapshot;
}

export function TelemetryStrip({ connection }: TelemetryStripProps) {
  const traffic = useLiveTraffic();
  const isConnected = connection.status === 'connected';
  const isTun = connection.mode === 'tun';

  return (
    <div className="grid grid-cols-3 gap-2.5">
      <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3.5 py-2.5">
        <div className="flex items-center gap-1.5 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)]">
          <ArrowDown className="h-3.5 w-3.5 text-[var(--md-success)]" />
          Загрузка
        </div>
        <div className="mt-0.5 text-[0.9375rem] font-semibold text-[var(--md-on-surface)] font-mono-num">
          {isConnected ? formatSpeed(traffic.rxBytesPerSec) : '—'}
        </div>
        <div className="mt-0.5 text-[0.66rem] text-[var(--md-on-surface-variant)]/85 font-mono-num">
          {isConnected ? `Всего: ${formatBytes(traffic.totalRxBytes)}` : 'Ожидание сессии'}
        </div>
      </div>

      <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3.5 py-2.5">
        <div className="flex items-center gap-1.5 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)]">
          <ArrowUp className="h-3.5 w-3.5 text-[var(--md-primary)]" />
          Отдача
        </div>
        <div className="mt-0.5 text-[0.9375rem] font-semibold text-[var(--md-on-surface)] font-mono-num">
          {isConnected ? formatSpeed(traffic.txBytesPerSec) : '—'}
        </div>
        <div className="mt-0.5 text-[0.66rem] text-[var(--md-on-surface-variant)]/85 font-mono-num">
          {isConnected ? `Всего: ${formatBytes(traffic.totalTxBytes)}` : 'Ожидание сессии'}
        </div>
      </div>

      <div className="rounded-2xl border border-[var(--md-outline-variant)] bg-[var(--md-surface-container-low)] px-3.5 py-2.5">
        <div className="flex items-center gap-1.5 text-[0.6875rem] font-medium text-[var(--md-on-surface-variant)]">
          {isConnected && isTun ? (
            <Shield className="h-3.5 w-3.5 text-[var(--md-success)]" />
          ) : isConnected ? (
            <Globe2 className="h-3.5 w-3.5 text-[var(--md-tertiary)]" />
          ) : (
            <HardDriveDownload className="h-3.5 w-3.5 text-[var(--md-on-surface-variant)]" />
          )}
          {isTun ? 'TUN-интерфейс' : 'Локальный узел'}
        </div>
        <div className="mt-0.5 text-[0.875rem] font-semibold text-[var(--md-on-surface)] font-mono-num truncate">
          {isConnected
            ? isTun
              ? 'TUN (весь ПК)'
              : connection.localHttpPort
                ? `127.0.0.1:${connection.localHttpPort}`
                : 'Активен'
            : 'Не активен'}
        </div>
        <div className="mt-0.5 text-[0.66rem] text-[var(--md-on-surface-variant)]/85">
          {isConnected
            ? isTun
              ? 'Весь трафик системы'
              : 'Системный прокси вкл.'
            : isTun
              ? 'TUN остановлен'
              : 'Системный прокси выкл.'}
        </div>
      </div>
    </div>
  );
}
